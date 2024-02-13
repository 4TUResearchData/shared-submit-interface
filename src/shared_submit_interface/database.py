"""This module provides the communication with the SPARQL endpoint."""

import os
import logging
import uuid
import secrets
from datetime import datetime
from urllib.error import URLError, HTTPError
from urllib.request import urlopen
from defusedxml import ElementTree
from rdflib import Dataset, Graph, Literal, RDF, XSD, URIRef
from rdflib.plugins.stores import sparqlstore
from rdflib.store import CORRUPTED_STORE, NO_STORE
from jinja2 import Environment, FileSystemLoader
from shared_submit_interface import cache, rdf
from shared_submit_interface.convenience import epoch_to_human_readable

class SparqlInterface:
    """This class reads and writes data from a SPARQL endpoint."""

    def __init__ (self):

        self.endpoint     = "http://127.0.0.1:8890/sparql"
        self.update_endpoint = None
        self.state_graph  = "ssi://default"
        self.log          = logging.getLogger(__name__)
        self.cache        = cache.CacheLayer(None)

        sparql_templates_path = os.path.join(os.path.dirname(__file__),
                                             "resources",
                                             "sparql_templates")
        self.jinja        = Environment(loader = FileSystemLoader(sparql_templates_path),
                                        autoescape = True)
        self.sparql       = None
        self.sparql_is_up = False
        self.enable_query_audit_log = False
        self.store        = None

    # SPARQL INTERACTION BITS
    # -------------------------------------------------------------------------

    def setup_sparql_endpoint (self):
        """Procedure to be called after setting the 'endpoint' members."""

        # BerkeleyDB as local RDF store.
        if (isinstance (self.endpoint, str) and self.endpoint.startswith("bdb://")):
            directory = self.endpoint[6:]
            self.sparql = Dataset("BerkeleyDB")
            self.sparql.open (directory, create=True)
            if not isinstance (self.sparql, Dataset):
                if self.sparql == CORRUPTED_STORE:
                    self.log.error ("'%s' is corrupted.", directory)
                elif self.sparql == NO_STORE:
                    self.log.error ("'%s' is not a BerkeleyDB store.", directory)
                else:
                    self.log.error ("Loading '%s' returned %s.", directory, self.sparql)
                return None
            self.log.info ("Using BerkeleyDB RDF store.")

        # External SPARQL endpoints, like Virtuoso.
        else:
            if self.update_endpoint is None:
                self.update_endpoint = self.endpoint

            self.store = sparqlstore.SPARQLUpdateStore(
                # Avoid rdflib from wrapping in a blank-node graph by setting
                # context_aware to False.
                context_aware   = False,
                query_endpoint  = self.endpoint,
                update_endpoint = self.update_endpoint,
                returnFormat    = "json",
                method          = "POST")
            # Set bind_namespaces so rdflib does not inject PREFIXes.
            self.sparql  = Graph(store = self.store, bind_namespaces = "none")
            self.log.info ("Using external RDF store.")

        self.sparql_is_up = True
        return None

    def __log_query (self, query, prefix="Query"):
        self.log.info ("%s:\n---\n%s\n---", prefix, query)

    def __query_from_template (self, name, args=None):
        template   = self.jinja.get_template (f"{name}.sparql")
        parameters = { "state_graph": self.state_graph }
        if args is None:
            args = {}

        return template.render ({ **args, **parameters })

    def __normalize_binding (self, row):
        output = {}
        for name in row.keys():
            if isinstance(row[name], Literal):
                xsd_type = row[name].datatype
                if xsd_type == XSD.integer:
                    if str(name).endswith("_date"):
                        output[str(name)] = epoch_to_human_readable (int(row[name]))
                    else:
                        output[str(name)] = int(float(row[name]))
                elif xsd_type == XSD.decimal:
                    output[str(name)] = int(float(row[name]))
                elif xsd_type == XSD.boolean:
                    try:
                        output[str(name)] = bool(int(row[name]))
                    except ValueError:
                        output[str(name)] = str(row[name]).lower() == "true"
                elif xsd_type == XSD.dateTime:
                    self.log.warning ("Using xsd:dateTime is deprecated.")
                    time_value = row[name].partition(".")[0]
                    if time_value[-1] == 'Z':
                        time_value = time_value[:-1]
                    if time_value.endswith("+00:00"):
                        time_value = time_value[:-6]
                    output[str(name)] = time_value
                elif xsd_type == XSD.date:
                    output[str(name)] = row[name]
                elif xsd_type == XSD.string:
                    if row[name] == "NULL":
                        output[str(name)] = None
                    else:
                        output[str(name)] = str(row[name])
                # bindings that were produced with BIND() on Virtuoso
                # have no XSD type.
                elif xsd_type is None:
                    output[str(name)] = str(row[name])
            elif row[name] is None:
                output[str(name)] = None
            else:
                output[str(name)] = str(row[name])

        return output

    def __run_query (self, query, cache_key_string=None, prefix=None, retries=5):

        cache_key = None
        if cache_key_string is not None:
            cache_key = self.cache.make_key (cache_key_string)
            cached    = self.cache.cached_value(prefix, cache_key)
            if cached is not None:
                return cached

        results = []
        try:
            execution_type, query_type = rdf.query_type (query)
            if execution_type == "update":
                self.sparql.update (query)
                # Upon failure, an exception is thrown.
                if self.enable_query_audit_log:
                    self.__log_query (query, "Query Audit Log")
                results = True
            elif execution_type == "gather":
                query_results = self.sparql.query(query)
                # ASK queries only return a boolean.
                if query_type == "ASK":
                    results = query_results.askAnswer
                elif isinstance(query_results, tuple):
                    self.log.error ("Error executing query (%s): %s",
                                    query_results[0], query_results[1])
                    self.__log_query (query)
                    return []
                else:
                    results = list(map(self.__normalize_binding,
                                       query_results.bindings))
            else:
                self.log.error ("Invalid query (%s, %s)", execution_type, query_type)
                self.__log_query (query)
                return []

            if cache_key_string is not None:
                self.cache.cache_value (prefix, cache_key, results, query)

            if not self.sparql_is_up:
                self.log.info ("Connection to the SPARQL endpoint seems up again.")
                self.sparql_is_up = True

        except HTTPError as error:
            if error.code == 400:
                self.log.error ("Badly formed SPARQL query:")
                self.__log_query (query)
            if error.code == 404:
                if self.sparql_is_up:
                    self.log.error ("Endpoint seems not to exist (anymore).")
                    self.sparql_is_up = False
            if error.code == 401:
                if self.sparql_is_up:
                    self.log.error ("Endpoint seems to require authentication.")
                    self.sparql_is_up = False
            if error.code == 503:
                if retries > 0:
                    self.log.warning ("Retrying SPARQL request due to service unavailability (%s)",
                                      retries)
                    return self.__run_query (query, cache_key_string=cache_key_string,
                                             prefix=prefix, retries=(retries - 1)) # pylint: disable=superfluous-parens

                self.log.warning ("Giving up on retrying SPARQL request.")

            self.log.error ("SPARQL endpoint returned %d:\n---\n%s\n---",
                            error.code, error.reason)
            return []
        except URLError:
            if self.sparql_is_up:
                self.log.error ("Connection to the SPARQL endpoint seems down.")
                self.sparql_is_up = False
                return []
        except AttributeError as error:
            self.log.error ("SPARQL query failed.")
            self.log.error ("Exception: %s", error)
            self.__log_query (query)
        except Exception as error:  # pylint: disable=broad-exception-caught
            self.log.error ("SPARQL query failed.")
            self.log.error ("Exception: %s: %s", type(error), error)
            self.__log_query (query)
            return []

        return results

    def __insert_query_for_graph (self, graph):
        if self.enable_query_audit_log:
            query = rdf.insert_query (self.state_graph, graph)
            self.__log_query (query, "Query Audit Log")
            return query
        return rdf.insert_query (self.state_graph, graph)

    def add_triples_from_graph (self, graph):
        """Inserts triples from GRAPH into the state graph."""

        # There's an upper limit to how many triples one can add in a single
        # INSERT query.  To stay on the safe side, we create batches of 250
        # triplets per INSERT query.

        counter             = 0
        processing_complete = True
        insertable_graph    = Graph()

        for subject, predicate, noun in graph:
            counter += 1
            insertable_graph.add ((subject, predicate, noun))
            if counter >= 250:
                query = self.__insert_query_for_graph (insertable_graph)
                if not self.__run_query (query):
                    processing_complete = False
                    break

                # Reset the graph by creating a new one.
                insertable_graph = Graph()
                counter = 0

        query = self.__insert_query_for_graph (insertable_graph)
        if not self.__run_query (query):
            processing_complete = False

        if processing_complete:
            return True

        self.log.error ("Inserting triples from a graph failed.")
        self.__log_query (query)

        return False

    def initialize_database (self, account_email=None):
        """Procedure to initialize the database."""

        # Do not re-initialize.
        is_initialized = self.__run_query (self.__query_from_template ("is_initialized"))
        if is_initialized:
            self.log.info ("Skipping re-initialization of the state-graph.")
            return True

        graph = Graph ()
        organizations = self.read_organizations_from_surf_idps_metadata ()
        for organization in organizations:
            uri = URIRef(rdf.uuid_to_uri (organization["uuid"], "organization"))
            rdf.add (graph, uri, RDF.type, rdf.SSI["Organization"], "uri")
            rdf.add (graph, uri, rdf.SSI["name"], organization["name"], XSD.string)
            rdf.add (graph, uri, rdf.SSI["url"], organization["url"], "uri")

        rdf.add (graph, URIRef("this"), rdf.SSI["initialized"], True, XSD.boolean)
        query = self.__insert_query_for_graph (graph)
        result = self.__run_query (query)
        if not result:
            self.log.error ("Failed to insert organizations.")

        if account_email:
            return self.insert_account (email=account_email)

        return True

    # USER SESSION BITS
    # -------------------------------------------------------------------------

    def insert_session (self, account_uuid, name=None, token=None, editable=False):
        """Procedure to add a session token for an account_uuid."""

        if account_uuid is None:
            return None, None, None

        account = self.account_by_uuid (account_uuid)
        if account is None:
            return None, None, None

        if token is None:
            token = secrets.token_hex (64)

        current_time = datetime.strftime (datetime.now(), "%Y-%m-%dT%H:%M:%SZ")

        graph       = Graph()
        link_uri    = rdf.unique_node ("session")
        account_uri = URIRef(rdf.uuid_to_uri (account_uuid, "account"))

        graph.add ((link_uri, RDF.type,                rdf.SSI["Session"]))
        graph.add ((link_uri, rdf.SSI["account"],      account_uri))
        graph.add ((link_uri, rdf.SSI["created_date"], Literal(current_time, datatype=XSD.dateTime)))
        graph.add ((link_uri, rdf.SSI["name"],         Literal(name, datatype=XSD.string)))
        graph.add ((link_uri, rdf.SSI["token"],        Literal(token, datatype=XSD.string)))
        graph.add ((link_uri, rdf.SSI["editable"],     Literal(editable, datatype=XSD.boolean)))
        graph.add ((link_uri, rdf.SSI["active"],       Literal(True, datatype=XSD.boolean)))

        if self.add_triples_from_graph (graph):
            return token, None, rdf.uri_to_uuid (link_uri)

        return None, None, None

    def update_session (self, account_uuid, session_uuid, name=None, active=None):
        """Procedure to edit a session."""

        query = self.__query_from_template ("update_session", {
            "account_uuid":  account_uuid,
            "session_uuid":  session_uuid,
            "name":          name,
            "active":        rdf.escape_boolean_value (active)
        })

        return self.__run_query (query)

    def delete_all_sessions (self):
        """Procedure to delete all sessions."""

        query = self.__query_from_template ("delete_sessions")
        return self.__run_query (query)

    def delete_inactive_session_by_uuid (self, session_uuid):
        """Procedure to remove an inactive session by its UUID alone."""

        query = self.__query_from_template ("delete_inactive_session_by_uuid", {
            "session_uuid": session_uuid
        })

        return self.__run_query (query)

    def delete_session_by_uuid (self, account_uuid, session_uuid):
        """Procedure to remove a session from the state graph."""

        query   = self.__query_from_template ("delete_session_by_uuid", {
            "session_uuid":  session_uuid,
            "account_uuid":  account_uuid
        })

        return self.__run_query (query)

    def delete_session (self, token):
        """Procedure to remove a session from the state graph."""

        if token is None:
            return True

        query = self.__query_from_template ("delete_session", {"token": token})
        return self.__run_query (query)

    def sessions (self, account_uuid, session_uuid=None, mfa_token=None):
        """Returns the sessions for an account."""

        query = self.__query_from_template ("account_sessions", {
            "account_uuid":  account_uuid,
            "session_uuid":  session_uuid,
            "mfa_token":     mfa_token
        })

        return self.__run_query (query)

    # ORGANIZATIONS
    # -------------------------------------------------------------------------

    def read_organizations_from_surf_idps_metadata (self):
        """Returns a list of organizations by querying SURFContext's identity provider metadata."""

        organizations = []
        with urlopen("https://metadata.surfconext.nl/idps-metadata.xml") as handler:
            tree = ElementTree.parse(handler)
            xml_root = tree.getroot()

            try:
                schema_ns = xml_root.attrib.get("{http://www.w3.org/2001/XMLSchema-instance}schemaLocation").split(" ")[0]
                xml_ns = "http://www.w3.org/XML/1998/namespace"
            except (AttributeError, IndexError):
                self.log.error ("Incompatible schema for SURF IDP metadata..")

            if xml_root.tag != f"{{{schema_ns}}}EntitiesDescriptor":
                self.log.error ("The SURF IDP metadata format seems to have changed.")
                return organizations

            organization_elements = xml_root.findall(f"{{{schema_ns}}}EntityDescriptor/{{{schema_ns}}}Organization")
            number_of_organizations = 0
            for element in organization_elements:
                try:
                    name = element.find (f"{{{schema_ns}}}OrganizationDisplayName[@{{{xml_ns}}}lang='en']").text
                    url = element.find (f"{{{schema_ns}}}OrganizationURL").text
                    identifier = uuid.uuid3 (uuid.NAMESPACE_URL, url.encode("utf-8"))
                    organizations.append({ "uuid": identifier, "name": name, "url": url })
                    number_of_organizations += 1
                except AttributeError:
                    self.log.warning ("Skipping organization due to missing metadata.")

            self.log.info ("Found %d organizations.", number_of_organizations)

        return organizations

    def organizations (self, organization_uuid=None, search_for=None):
        """Returns a list of organizations on success or None on failure."""
        query = self.__query_from_template ("organizations", {
            "uuid": organization_uuid,
            "search_for": search_for
        })
        return self.__run_query (query)

    # DATASETS
    # -------------------------------------------------------------------------

    def datasets (self, dataset_uuid=None):
        """Returns a list of datasets on success or None on failure."""
        query = self.__query_from_template ("datasets", { "uuid": dataset_uuid })
        return self.__run_query (query)

    def create_dataset (self):
        """Creates a dataset and returns a unique UUID."""

        graph = Graph()
        uri = rdf.unique_node ("dataset")

        graph.add ((uri, RDF.type, rdf.SSI["Dataset"]))
        current_epoch = int(datetime.now().timestamp())
        rdf.add (graph, uri, rdf.SSI["is_editable"],      True)
        rdf.add (graph, uri, rdf.SSI["is_transfered"],    False)
        rdf.add (graph, uri, rdf.SSI["created_date"],     current_epoch, XSD.integer)
        rdf.add (graph, uri, rdf.SSI["modified_date"],    current_epoch, XSD.integer)

        if not self.add_triples_from_graph (graph):
            return None

        return rdf.uri_to_uuid (uri)

    def update_dataset (self, dataset_uuid, title, affiliation, description, email, is_editable, is_transfered):
        """Updates the metadata of a dataset."""

        current_epoch = int(datetime.now().timestamp())
        query = self.__query_from_template("update_dataset", {
            "uuid": dataset_uuid,
            "title": rdf.escape_string_value (title),
            "affiliation": rdf.uuid_to_uri (affiliation, "organization"),
            "description": rdf.escape_string_value (description),
            "email": rdf.escape_string_value (email),
            "is_editable": rdf.escape_boolean_value (is_editable),
            "is_transfered": rdf.escape_boolean_value (is_transfered),
            "modified_date": current_epoch
        })

        return self.__run_query (query)

    # ACCOUNTS
    # -------------------------------------------------------------------------

    def insert_account (self, email=None, first_name=None, last_name=None):
        """Procedure to create an account."""

        graph       = Graph()
        account_uri = rdf.unique_node ("account")

        if isinstance (email, str):
            email = email.lower()

        rdf.add (graph, account_uri, RDF.type,              rdf.SSI["Account"], "uri")
        rdf.add (graph, account_uri, rdf.SSI["first_name"], first_name, XSD.string)
        rdf.add (graph, account_uri, rdf.SSI["last_name"],  last_name,  XSD.string)
        rdf.add (graph, account_uri, rdf.SSI["email"],      email,      XSD.string)

        if self.add_triples_from_graph (graph):
            return rdf.uri_to_uuid (account_uri)

        return None

    def accounts (self, account_uuid=None, order=None, order_direction=None,
                  limit=None, offset=None, is_active=None, email=None):
        """Returns accounts."""

        query = self.__query_from_template ("accounts", {
            "account_uuid": account_uuid,
            "is_active": is_active,
            "email": rdf.escape_string_value(email),
        })
        query += rdf.sparql_suffix (order, order_direction, limit, offset)
        return self.__run_query (query, query, "accounts")

    def account_by_session_token (self, session_token):
        """Returns an account record or None."""

        if session_token is None:
            return None

        query = self.__query_from_template ("account_by_session_token", {
            "token":       rdf.escape_string_value (session_token),
        })

        results = self.__run_query (query)
        return results[0] if results else None

    def account_by_uuid (self, account_uuid):
        """Returns an account record or None."""

        results = self.accounts(account_uuid)
        if results:
            return results[0]

        return None

    def account_by_email (self, email):
        """Returns the account matching EMAIL."""

        query = self.__query_from_template ("account_by_email", {
            "email":  rdf.escape_string_value (email)
        })

        results = self.__run_query (query)
        return results[0] if results else None
