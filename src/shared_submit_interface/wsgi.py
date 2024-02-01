"""This module implements the entire HTTP interface."""

import json
import os
import logging
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
            R("/",                             self.ui_home),
            R("/organizations",                self.organizations),
            R("/datasets",                     self.datasets),
            R("/draft-dataset",                self.draft_dataset),
            R("/draft-dataset/<dataset_uuid>", self.draft_dataset),
            R("/robots.txt",                   self.robots_txt),
            R("/repositories",                    self.repositories),
        ])
        self.allow_crawlers   = False
        self.maintenance_mode = False
        self.base_url         = f"http://{address}:{port}"
        self.db               = database.SparqlInterface()  # pylint: disable=invalid-name
        self.repositories     = {}
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
            template      = self.jinja.get_template (template_name)
            parameters    = {
                "base_url": self.base_url,
                "path":     request.path,
            }
            return self.response (template.render({ **context, **parameters }),
                                  mimetype='text/html')
        except TemplateNotFound:
            self.log.error ("Jinja2 template not found: '%s'.", template_name)

        return self.error_500 ()

    ## REQUEST CHECKERS
    ## ------------------------------------------------------------------------

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

    ## ERROR HANDLERS
    ## ------------------------------------------------------------------------

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

    def ui_home (self, request):  # pylint: disable=unused-argument
        """Implements /."""
        return self.__render_template (request, "home.html")

    def robots_txt (self, request):  # pylint: disable=unused-argument
        """Implements /robots.txt."""

        output = "User-agent: *\n"
        if self.allow_crawlers:
            output += "Allow: /\n"
        else:
            output += "Disallow: /\n"

        return self.response (output, mimetype="text/plain")

    def ui_maintenance (self, request):
        """Implements a maintenance page."""

        if self.accepts_html (request):
            return self.__render_template (request, "maintenance.html")

        return self.response (json.dumps({ "status": "maintenance" }))

    def organizations (self, request):
        """Implements /organizations"""

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

        return self.error_406 ("GET")

    def repositories (self, request):
        """Implements /repositories."""

        if request.method in ("GET", "HEAD"):
            repositories = list(map(lambda name: { "name": name, **self.repositories[name] }, self.repositories.keys()))
            return self.default_list_response (repositories, formatter.repository_record)
    def datasets (self, request):
        """Implements /datasets"""

        if request.method in ("GET", "HEAD"):
            datasets = self.db.datasets ()
            return self.default_list_response (datasets, formatter.dataset_record)

        return self.error_406 ("GET")

    def draft_dataset (self, request, dataset_uuid=None):
        """Implements /draft-dataset."""

        if request.method in ("GET", "HEAD"):
            if dataset_uuid is None:
                dataset_uuid = self.db.create_dataset ()
                if dataset_uuid is None:
                    return self.error_500 ()
                return redirect (f"/draft-dataset/{dataset_uuid}", code=302)

            try:
                dataset = self.db.datasets(dataset_uuid=dataset_uuid)[0]
                return self.__render_template (request, "edit-dataset.html", dataset=dataset)
            except IndexError:
                return self.error_403 (request)

        if request.method == "PUT":
            if dataset_uuid is None or not validator.is_valid_uuid (dataset_uuid):
                return self.error_403 (request)

            try:
                dataset = self.db.datasets(dataset_uuid=dataset_uuid)[0]
            except IndexError:
                return self.error_403 (request)

            errors = []
            record = request.get_json()
            parameters = {
                "dataset_uuid":  dataset_uuid,
                "title":         validator.string_value (record, "title", 0, 255, False, error_list=errors),
                "affiliation":   validator.uuid_value (record, "affiliation", False, error_list=errors),
                "description":   validator.string_value (record, "description", 0, 4096, False, error_list=errors),
                "email":         validator.string_value (record, "email", 0, 512, False, error_list=errors),
                "is_editable":   dataset["is_editable"],
                "is_transfered": dataset["is_transfered"]
            }

            if errors:
                return self.error_400_list (request, errors)

            if self.db.update_dataset (**parameters):
                return self.respond_204 ()

        return self.error_406 (["GET", "PUT"])
