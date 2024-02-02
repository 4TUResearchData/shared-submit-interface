"""This module provides the communication with the SPARQL endpoint."""

import os
import logging
import uuid
from datetime import datetime
from urllib.error import URLError, HTTPError
from urllib.request import urlopen
from defusedxml import ElementTree
from rdflib import Dataset, Graph, Literal, RDF, XSD, URIRef
from rdflib.plugins.stores import sparqlstore
from rdflib.store import CORRUPTED_STORE, NO_STORE
from jinja2 import Environment, FileSystemLoader
from shared_submit_interface import cache, rdf

class SparqlInterface:
    """This class reads and writes data from a SPARQL endpoint."""

    def __init__ (self):

        self.endpoint     = "http://127.0.0.1:8890/sparql"
        self.update_endpoint = None
        self.state_graph  = "ssi://default"
        self.log          = logging.getLogger(__name__)
        self.cache        = cache.CacheLayer(None)
        self.jinja        = Environment(loader = FileSystemLoader(
                            os.path.join(os.path.dirname(__file__),
                                         "resources/sparql_templates")),
                                        autoescape=True)
        self.sparql       = None
        self.sparql_is_up = False
        self.enable_query_audit_log = False
        self.store        = None

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
                ## Upon failure, an exception is thrown.
                if self.enable_query_audit_log:
                    self.__log_query (query, "Query Audit Log")
                results = True
            elif execution_type == "gather":
                query_results = self.sparql.query(query)
                ## ASK queries only return a boolean.
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
                                             prefix=prefix, retries=retries-1)

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

        ## There's an upper limit to how many triples one can add in a single
        ## INSERT query.  To stay on the safe side, we create batches of 250
        ## triplets per INSERT query.

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

    def initialize_database (self):
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
        return self.__run_query (query)

    def organizations (self, organization_uuid=None, search_for=None):
        """Returns a list of organizations on success or None on failure."""
        query = self.__query_from_template ("organizations", {
            "uuid": organization_uuid,
            "search_for": search_for
        })
        return self.__run_query (query)

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
