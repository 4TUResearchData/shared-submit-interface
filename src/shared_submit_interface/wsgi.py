"""This module implements the entire HTTP interface."""

import json
import os
import logging
import requests
from werkzeug.utils import redirect
from werkzeug.wrappers import Request, Response
from werkzeug.routing import Map, Rule
from werkzeug.middleware.shared_data import SharedDataMiddleware
from werkzeug.exceptions import HTTPException, NotFound, BadRequest
from jinja2 import Environment, FileSystemLoader
from jinja2.exceptions import TemplateNotFound
from shared_submit_interface import database
from shared_submit_interface import validator
from shared_submit_interface import formatter
from shared_submit_interface.convenience import value_or_none

# Error handling for loading python3-saml is done in 'ui'.
# So if it fails here, we can safely assume we don't need it.
try:
    from onelogin.saml2.auth import OneLogin_Saml2_Auth
    from onelogin.saml2.errors import OneLogin_Saml2_Error
except (ImportError, ModuleNotFoundError):
    pass


def R (uri_path, endpoint):  # pylint: disable=invalid-name
    """
    Short-hand for defining a route between a URI and its
    entry-point procedure.
    """
    return Rule (uri_path, endpoint=endpoint)


class WebUserInterfaceServer:
    """This class implements the HTTP interaction for the web user interface."""

    def __init__ (self, address="127.0.0.1", port=8080):

        self.url_map          = Map([
            R("/",                                self.ui_home),
            R("/api/v1/accounts",                 self.api_v1_accounts),
            R("/api/v1/organizations",            self.api_v1_organizations),
            R("/api/v1/repositories",             self.api_v1_repositories),
            R("/api/v1/datasets",                 self.api_v1_datasets),
            R("/api/v1/dataset/<dataset_uuid>",   self.api_v1_dataset),
            R("/api/v1/recommend-repository/<dataset_uuid>", self.api_v1_recommend_data_repository),
            R("/draft-dataset",                   self.ui_draft_dataset),
            R("/saml/metadata",                   self.saml_metadata),
            R("/saml/login",                      self.ui_login),
            R("/login",                           self.ui_login),
            R("/logout",                          self.ui_logout),
            R("/my-datasets",                     self.ui_my_datasets),
            R("/draft-dataset/<dataset_uuid>",    self.ui_draft_dataset),
            R("/transfer-dataset/<dataset_uuid>", self.transfer_dataset),
            R("/robots.txt",                      self.robots_txt),
        ])
        self.allow_crawlers   = False
        self.maintenance_mode = False
        self.base_url         = f"http://{address}:{port}"
        self.cookie_key       = "ssi_session"
        self.db               = database.SparqlInterface()  # pylint: disable=invalid-name
        self.repositories     = {}
        self.identity_provider = None
        self.saml_config_path = None
        self.saml_config      = None
        self.automatic_login_email = None
        self.in_production    = False

        resources_path        = os.path.dirname(__file__)
        self.jinja            = Environment(loader = FileSystemLoader([
            os.path.join(resources_path, "resources", "html_templates"),
            "/"
        ]), autoescape=True)
        self.static_roots     = {
            "/robots.txt": os.path.join(resources_path, "resources", "robots.txt"),
            "/static":     os.path.join(resources_path, "resources", "static")
        }
        self.log_access       = self.log_access_directly
        self.log              = logging.getLogger(__name__)
        self.wsgi             = SharedDataMiddleware(self.__respond, self.static_roots)
        self.using_uwsgi      = False

        logging.getLogger('werkzeug').setLevel(logging.ERROR)

    def __call__ (self, environ, start_response):
        return self.wsgi (environ, start_response)

    def __dispatch_request (self, request):
        adapter = self.url_map.bind_to_environ(request.environ)
        try:
            self.log_access (request)
            if self.maintenance_mode:
                return self.ui_maintenance (request)
            endpoint, values = adapter.match() #  pylint: disable=unpacking-non-sequence
            return endpoint (request, **values)
        except NotFound:
            return self.error_404 (request)
        except BadRequest as error:
            self.log.error ("Received bad request: %s", error)
            return self.error_400 (request, error.description, 400)
        except HTTPException as error:
            self.log.error ("Unknown error in dispatch_request: %s", error)
            return error
        # Broad catch-all to improve logging/debugging of such situations.
        except Exception as error:
            self.log.error ("In request: %s", request.environ)
            raise error

    def __respond (self, environ, start_response):
        request  = Request(environ)
        response = self.__dispatch_request(request)
        return response(environ, start_response)

    def __render_template (self, request, template_name, **context):
        try:
            template   = self.jinja.get_template (template_name)
            token      = self.token_from_cookie (request)
            account    = self.db.account_by_session_token (token)
            parameters = {
                "base_url":     self.base_url,
                "path":         request.path,
                "is_logged_in": account is not None,

            }
            return self.response (template.render({ **context, **parameters }),
                                  mimetype='text/html')
        except TemplateNotFound:
            self.log.error ("Jinja2 template not found: '%s'.", template_name)

        return self.error_500 ()

    # REQUEST CHECKERS
    # -------------------------------------------------------------------------

    def accepts_content_type (self, request, content_type, strict=True):
        """Procedure to check whether the client accepts a content type."""
        try:
            acceptable = request.headers['Accept']
            if not acceptable:
                return False

            exact_match  = content_type in acceptable
            if strict:
                return exact_match

            global_match = "*/*" in acceptable
            return global_match or exact_match
        except KeyError:
            return False

    def accepts_html (self, request):
        """Procedure to check whether the client accepts HTML."""
        return self.accepts_content_type (request, "text/html")

    def accepts_plain_text (self, request):
        """Procedure to check whether the client accepts plain text."""
        return (self.accepts_content_type (request, "text/plain") or
                self.accepts_content_type (request, "*/*"))

    def accepts_xml (self, request):
        """Procedure to check whether the client accepts XML."""
        return (self.accepts_content_type (request, "application/xml") or
                self.accepts_content_type (request, "text/xml"))

    def accepts_json (self, request):
        """Procedure to check whether the client accepts JSON."""
        return self.accepts_content_type (request, "application/json", strict=False)

    # ERROR HANDLERS
    # -------------------------------------------------------------------------

    def error_authorization_failed (self, request):
        """Procedure to handle authorization failures."""
        if self.accepts_html (request):
            response = self.__render_template (request, "403.html")
        else:
            response = self.response (json.dumps({
                "message": "Invalid or unknown session token",
                "code":    "InvalidSessionToken"
            }))

        response.status_code = 403
        return response

    def error_400_list (self, request, errors):
        """Procedure to respond with HTTP 400 with a list of error messages."""
        response = None
        if self.accepts_html (request):
            response = self.__render_template (request, "400.html", message=errors)
        else:
            response = self.response (json.dumps(errors))
        response.status_code = 400
        return response

    def error_400 (self, request, message, code):
        """Procedure to respond with HTTP 400 with a single error message."""
        return self.error_400_list (request, {
            "message": message,
            "code":    code
        })

    def error_403 (self, request):
        """Procedure to respond with HTTP 403."""
        response = None
        if self.accepts_html (request):
            response = self.__render_template (request, "403.html")
        else:
            response = self.response (json.dumps({
                "message": "Not allowed."
            }))
        response.status_code = 403
        return response

    def error_404 (self, request):
        """Procedure to respond with HTTP 404."""
        response = None
        if self.accepts_html (request):
            response = self.__render_template (request, "404.html")
        else:
            response = self.response (json.dumps({
                "message": "This resource does not exist."
            }))
        response.status_code = 404
        return response

    def error_405 (self, allowed_methods):
        """Procedure to respond with HTTP 405."""
        response = self.response (f"Acceptable methods: {allowed_methods}",
                                  mimetype="text/plain")
        response.status_code = 405
        return response

    def error_406 (self, allowed_formats):
        """Procedure to respond with HTTP 406."""
        response = self.response (f"Acceptable formats: {allowed_formats}",
                                  mimetype="text/plain")
        response.status_code = 406
        return response

    def error_500 (self):
        """Procedure to respond with HTTP 500."""
        response = self.response ("")
        response.status_code = 500
        return response

    # CONVENIENCE
    # -------------------------------------------------------------------------

    def token_from_cookie (self, request, cookie_key=None):
        """Procedure to gather an access token from a HTTP cookie."""
        if cookie_key is None:
            cookie_key = self.cookie_key
        return value_or_none (request.cookies, cookie_key)

    def token_from_request (self, request):
        """Procedure to get the access token from a HTTP request."""
        try:
            token_string = self.token_from_cookie (request)
            if token_string is None:
                token_string = request.environ["HTTP_AUTHORIZATION"]
            if isinstance(token_string, str) and token_string.startswith("token "):
                token_string = token_string[6:]
            return token_string
        except KeyError:
            return None

    def account_uuid_from_request (self, request):
        """Procedure to the account UUID for a HTTP request."""
        token = self.token_from_request (request)
        account = self.db.account_by_session_token (token)
        if account is None:
            self.log.error ("Attempt to authenticate with %s failed.", token)
            return None
        return value_or_none (account, "uuid")

    def default_error_handling (self, request, methods, content_type):
        """Procedure to handle both method and content type mismatches."""
        if isinstance (methods, str):
            methods = [methods]

        if (request.method not in methods and
            (not ("GET" in methods and request.method == "HEAD"))):
            return self.error_405 (methods)

        if not self.accepts_content_type (request, content_type, strict=False):
            return self.error_406 (content_type)

        return None

    def default_authenticated_error_handling (self, request, methods, content_type):
        """Procedure to handle method and content type mismatches as well authentication."""

        handler = self.default_error_handling (request, methods, content_type)
        if handler is not None:
            return handler

        account_uuid = self.account_uuid_from_request (request)
        if account_uuid is None:
            return self.error_authorization_failed (request)

        return account_uuid

    def default_list_response (self, records, format_function, **parameters):
        """Procedure to respond a list of items."""
        output     = []
        try:
            for record in records:
                output.append(format_function ({ **parameters, **record}))
        except TypeError:
            self.log.error ("%s: A TypeError occurred.", format_function)

        return self.response (json.dumps(output))

    def respond_204 (self):
        """Procedure to respond with HTTP 204."""
        return Response("", 204, {})

    def response (self, content, mimetype='application/json'):
        """Returns a self.response object with some tweaks."""
        return Response(content, mimetype=mimetype)

    def log_access_using_x_forwarded_for (self, request):
        """Log interactions using the X-Forwarded-For header."""
        try:
            self.log.access ("%s requested %s %s.",  # pylint: disable=no-member
                             request.headers["X-Forwarded-For"],
                             request.method,
                             request.full_path)
        except KeyError:
            self.log.error ("Missing X-Forwarded-For header.")

    def log_access_directly (self, request):
        """Log interactions using the 'remote_addr' property."""
        self.log.access ("%s requested %s %s.",  # pylint: disable=no-member
                         request.remote_addr,
                         request.method,
                         request.full_path)

    # SAML AUTHENTICATION
    # -------------------------------------------------------------------------

    def __request_to_saml_request (self, request):
        """Turns a werkzeug request into one that python3-saml understands."""

        return {
            # Always assume HTTPS.  A proxy server may mask it.
            "https":       "on",
            # Override the internal HTTP host because a proxy server masks the
            # actual HTTP host used.  Fortunately, we pre-configure the
            # expected HTTP host in the form of the "base_url".  So we strip
            # off the protocol prefix.
            "http_host":   self.base_url.split("://")[1],
            "script_name": request.path,
            "get_data":    request.args.copy(),
            "post_data":   request.form.copy()
        }

    def __saml_auth (self, request):
        """Returns an instance of OneLogin_Saml2_Auth."""
        http_fields = self.__request_to_saml_request (request)
        return OneLogin_Saml2_Auth (http_fields, custom_base_path=self.saml_config_path)

    def authenticate_using_saml (self, request):
        """Returns a record upon success, None otherwise."""

        http_fields = self.__request_to_saml_request (request)
        saml_auth   = OneLogin_Saml2_Auth (http_fields, custom_base_path=self.saml_config_path)
        try:
            saml_auth.process_response ()
        except OneLogin_Saml2_Error as error:
            if error.code == OneLogin_Saml2_Error.SAML_RESPONSE_NOT_FOUND:
                self.log.error ("Missing SAMLResponse in POST data.")
            else:
                self.log.error ("SAML error %d occured.", error.code)
            return None

        errors = saml_auth.get_errors()
        if errors:
            self.log.error ("Errors in the SAML authentication:")
            self.log.error ("%s", ", ".join(errors))
            return None

        if not saml_auth.is_authenticated():
            self.log.error ("SAML authentication failed.")
            return None

        # Gather SAML session information.
        session = {}
        session['samlNameId']                = saml_auth.get_nameid()
        session['samlNameIdFormat']          = saml_auth.get_nameid_format()
        session['samlNameIdNameQualifier']   = saml_auth.get_nameid_nq()
        session['samlNameIdSPNameQualifier'] = saml_auth.get_nameid_spnq()
        session['samlSessionIndex']          = saml_auth.get_session_index()

        # Gather attributes from user.
        record               = {}
        attributes           = saml_auth.get_attributes()
        record["session"]    = session
        try:
            record["email"]      = attributes["urn:mace:dir:attribute-def:mail"][0]
            record["first_name"] = attributes["urn:mace:dir:attribute-def:givenName"][0]
            record["last_name"]  = attributes["urn:mace:dir:attribute-def:sn"][0]
            record["common_name"] = attributes["urn:mace:dir:attribute-def:cn"][0]
        except (KeyError, IndexError):
            self.log.error ("Didn't receive expected fields in SAMLResponse.")
            self.log.error ("Received attributes: %s", attributes)

        if not record["email"]:
            self.log.error ("Didn't receive required fields in SAMLResponse.")
            self.log.error ("Received attributes: %s", attributes)
            return None

        return record

    def saml_metadata (self, request):
        """Communicates the service provider metadata for SAML 2.0."""

        if not (self.accepts_content_type (request, "application/samlmetadata+xml") or
                self.accepts_xml (request)):
            return self.error_406 ("text/xml")

        if self.identity_provider != "saml":
            return self.error_404 (request)

        saml_auth   = self.__saml_auth (request)
        settings    = saml_auth.get_settings ()
        metadata    = settings.get_sp_metadata ()
        errors      = settings.validate_metadata (metadata)
        if len(errors) == 0:
            return self.response (metadata, mimetype="text/xml")

        self.log.error ("SAML SP Metadata validation failed.")
        self.log.error ("Errors: %s", ", ".join(errors))
        return self.error_500 ()

    # ENDPOINTS
    # -------------------------------------------------------------------------

    def robots_txt (self, request):  # pylint: disable=unused-argument
        """Implements /robots.txt."""

        output = "User-agent: *\n"
        if self.allow_crawlers:
            output += "Allow: /\n"
        else:
            output += "Disallow: /\n"

        return self.response (output, mimetype="text/plain")

    def api_v1_accounts (self, request):
        """Implements /api/v1/accounts."""

        if request.method in ("GET", "HEAD"):
            accounts = self.db.accounts ()
            return self.default_list_response (accounts, formatter.account_record)
        return self.error_406 ("GET")

    def api_v1_organizations (self, request):
        """Implements /api/v1/organizations."""

        if request.method in ("GET", "HEAD"):
            organizations = self.db.organizations ()
            return self.default_list_response (organizations, formatter.organization_record)

        if request.method == "POST":
            errors = []
            record = request.get_json()
            parameters = {
                "search_for": validator.string_value (record, "search_for", 0, 255, False, error_list=errors)
            }

            if errors:
                return self.error_400_list (request, errors)

            organizations = self.db.organizations (**parameters)
            return self.default_list_response (organizations, formatter.organization_record)

        return self.error_405 ("GET")

    def api_v1_repositories (self, request):
        """Implements /api/v1/repositories."""

        if request.method in ("GET", "HEAD"):
            repositories = list(map(lambda name: { "name": name, **self.repositories[name] }, self.repositories.keys()))
            return self.default_list_response (repositories, formatter.repository_record)

        return self.error_405 ("GET")

    def api_v1_datasets (self, request):
        """Implements /api/v1/datasets"""

        if request.method in ("GET", "HEAD"):
            datasets = self.db.datasets ()
            return self.default_list_response (datasets, formatter.dataset_record)

        return self.error_405 ("GET")

    def api_v1_dataset (self, request, dataset_uuid):
        """Implements /api/v1/dataset/<dataset_uuid>."""
        account_uuid = self.default_authenticated_error_handling (request, "PUT", "application/json")
        if isinstance (account_uuid, Response):
            return account_uuid

        if not validator.is_valid_uuid (dataset_uuid):
            return self.error_403 (request)

        try:
            dataset = self.db.datasets (dataset_uuid=dataset_uuid)[0]
        except IndexError:
            return self.error_404 (request)

        errors = []
        record = request.get_json()
        parameters = {
            "account_uuid":  account_uuid,
            "dataset_uuid":  dataset_uuid,
            "title":         validator.string_value (record, "title", 0, 255, False, error_list=errors),
            "affiliation":   validator.uuid_value (record, "affiliation", False, error_list=errors),
            "domain":        validator.uuid_value (record, "domain", False, error_list=errors),
            "datatype":      validator.uuid_value (record, "datatype", False, error_list=errors),
            "description":   validator.string_value (record, "description", 0, 4096, False, error_list=errors),
            "email":         validator.string_value (record, "email", 0, 512, False, error_list=errors),
            "is_editable":   dataset["is_editable"],
            "is_transfered": dataset["is_transfered"]
        }

        if errors:
            return self.error_400_list (request, errors)

        if not self.db.update_dataset (**parameters):
            return self.error_500 ()

        return self.respond_204 ()

    def api_v1_recommend_data_repository (self, request, dataset_uuid, transfer=False):
        """Implements /v1/recommend-repository/<dataset_uuid>."""

        account_uuid = self.default_authenticated_error_handling (request, "GET", "application/json")
        if isinstance (account_uuid, Response):
            return account_uuid

        if not validator.is_valid_uuid (dataset_uuid):
            return self.error_403 (request)

        try:
            dataset = self.db.datasets (account_uuid = account_uuid,
                                        dataset_uuid = dataset_uuid)[0]

            if value_or_none (dataset, "affiliation_uuid") is None:
                return self.error_400 (request,
                                       "Please provide your affiliation.",
                                       "NeedMoreData")
            if value_or_none (dataset, "domain_uuid") is None:
                return self.error_400 (request,
                                       "Please provide your research domain.",
                                       "NeedMoreData")
            if value_or_none (dataset, "datatype_uuid") is None:
                return self.error_400 (request,
                                       "Please provide the type of your data.",
                                       "NeedMoreData")

            repository = self.db.recommend_data_repository (account_uuid = account_uuid,
                                                            dataset_uuid = dataset_uuid)
            if not repository:
                self.log.error ("No repository recommendation possible for %s", dataset_uuid)
                self.error_500 ()

            if transfer:
                try:
                    settings = self.repositories[repository]
                    psk = settings["psk"]
                    base_url = settings["base-url"]
                    endpoint = settings["endpoint"]
                    record = {
                        "psk":    psk,
                        "email":  dataset["account_email"],
                        "title":  dataset["title"],
                        "domain": dataset["domain_name"],
                        "affiliation": "",
                        "datatype": ""
                    }
                    headers = {
                        "Accept": "application/json",
                        "Content-Type": "application/json"
                    }
                    response = requests.put (f"{base_url}{endpoint}",
                                             headers = headers,
                                             json = record,
                                             timeout = 10,
                                             allow_redirects = False)

                    if response.status_code == 302:
                        location = response.headers.get("location")
                        if location is None:
                            self.log.error ("No redirect location found for '%s'", dataset_uuid)
                            return self.error_500 ()

                        set_cookie = response.headers.get("set-cookie")
                        if set_cookie is None:
                            self.log.error ("No session cookie found for '%s'", dataset_uuid)
                            return self.error_500 ()

                        cookie = set_cookie.split(";")[0].split("=")
                        if len(cookie) != 2:
                            self.log.error ("Unexpected parsing of cookie.")
                            return self.error_500 ()

                        repository_redirect = redirect (f"{base_url}{location}", code=302)
                        repository_redirect.set_cookie (key=cookie[0], value=cookie[1])

                        if self.db.update_dataset (account_uuid=account_uuid,
                                                   dataset_uuid=dataset_uuid,
                                                   email=dataset["account_email"],
                                                   title=dataset["title"],
                                                   affiliation=dataset["affiliation_uuid"],
                                                   description=None,
                                                   is_editable=False,
                                                   is_transfered=True,
                                                   domain=dataset["domain_uuid"],
                                                   datatype=dataset["datatype_uuid"]):
                            return repository_redirect

                        return self.error_500()

                    self.log.error ("The data repository '%s' returned %s.",
                                    repository, response.status_code)
                    return self.error_500 ()
                except KeyError as error:
                    self.log.error ("Missing repository configuration for '%s' (%s)", repository, error)
                    return self.error_500 ()

            return self.response (json.dumps({ "repository": repository }))

        except IndexError:
            return self.error_404 (request)

    def ui_home (self, request):  # pylint: disable=unused-argument
        """Implements /."""
        return self.__render_template (request, "home.html")

    def ui_maintenance (self, request):
        """Implements a maintenance page."""

        if self.accepts_html (request):
            return self.__render_template (request, "maintenance.html")

        return self.response (json.dumps({ "status": "maintenance" }))

    def ui_login (self, request):
        """Implements /login."""

        account_uuid = None
        account      = None

        # Automatic log in for development purposes only.
        # ---------------------------------------------------------------------
        if self.automatic_login_email is not None and not self.in_production:
            account = self.db.account_by_email (self.automatic_login_email)
            if account is None:
                return self.error_403 (request)
            account_uuid = account["uuid"]
            self.log.access ("Account %s logged in via auto-login.", account_uuid) #  pylint: disable=no-member

        # SAML 2.0 authentication
        # ---------------------------------------------------------------------
        elif self.identity_provider == "saml":

            # Initiate the login procedure.
            if request.method == "GET":
                saml_auth   = self.__saml_auth (request)
                redirect_url = saml_auth.login()
                response    = redirect (redirect_url)

                return response

            # Retrieve signed data from SURFConext via the user.
            if request.method == "POST":
                if not self.accepts_html (request):
                    return self.error_406 ("text/html")

                saml_record = self.authenticate_using_saml (request)
                if saml_record is None:
                    return self.error_403 (request)

                try:
                    if "email" not in saml_record:
                        return self.error_400 (request, "Invalid request", "MissingEmailProperty")

                    account = self.db.account_by_email (saml_record["email"])
                    if account:
                        account_uuid = account["uuid"]
                        self.log.access ("Account %s logged in via SAML.", account_uuid) #  pylint: disable=no-member
                    else:
                        account_uuid = self.db.insert_account (
                            email      = saml_record["email"],
                            first_name = value_or_none (saml_record, "first_name"),
                            last_name  = value_or_none (saml_record, "last_name")
                        )
                        self.log.access ("Account %s created via SAML.", account_uuid) #  pylint: disable=no-member

                except TypeError:
                    pass
        else:
            self.log.error ("Unknown identity provider '%s'", self.identity_provider)
            return self.error_500()

        if account_uuid is not None:
            token, _, session_uuid = self.db.insert_session (account_uuid, name="Website login")
            if session_uuid is None:
                self.log.error ("Failed to create a session for account %s.", account_uuid)
                return self.error_500 ()

            self.log.access ("Created session %s for account %s.", session_uuid, account_uuid) #  pylint: disable=no-member

            response = redirect ("/draft-dataset", code=302)
            response.set_cookie (key=self.cookie_key, value=token, secure=self.in_production)
            return response

        return self.error_500 ()

    def ui_logout (self, request):
        """Implements /logout."""
        if not self.accepts_html (request):
            return self.error_406 ("text/html")

        response = redirect ("/", code=302)
        self.db.delete_session (self.token_from_cookie (request))
        response.delete_cookie (key=self.cookie_key)
        return response

    def ui_my_datasets (self, request):
        """Implements /my-datasets."""
        account_uuid = self.default_authenticated_error_handling (request, "GET", "text/html")
        if isinstance (account_uuid, Response):
            return account_uuid

        datasets = self.db.datasets (account_uuid = account_uuid)
        return self.__render_template (request, "my-datasets.html", datasets=datasets)

    def ui_draft_dataset (self, request, dataset_uuid=None):
        """Implements /draft-dataset."""

        account_uuid = self.default_authenticated_error_handling (request, "GET", "text/html")
        if isinstance (account_uuid, Response):
            return account_uuid

        if request.method in ("GET", "HEAD"):
            if dataset_uuid is None:
                dataset_uuid = self.db.create_dataset (account_uuid)
                if dataset_uuid is None:
                    return self.error_500 ()
                return redirect (f"/draft-dataset/{dataset_uuid}", code=302)

            try:
                dataset = self.db.datasets(dataset_uuid=dataset_uuid)[0]
                research_domains = self.db.research_domains ()
                datatypes = self.db.datatypes ()
                return self.__render_template (request, "edit-dataset.html",
                                               dataset          = dataset,
                                               research_domains = research_domains,
                                               datatypes        = datatypes)
            except IndexError:
                self.log.error ("Could not find draft dataset.")
                return self.error_403 (request)

        return self.error_405 ("GET")

    def transfer_dataset (self, request, dataset_uuid):
        """Implements /transfer-dataset/<dataset_uuid>."""
        return self.api_v1_recommend_data_repository (request, dataset_uuid, transfer=True)
