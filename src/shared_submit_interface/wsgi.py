"""This module implements the entire HTTP interface."""

import json
import os
import logging
from werkzeug.wrappers import Request, Response
from werkzeug.routing import Map, Rule
from werkzeug.middleware.shared_data import SharedDataMiddleware
from werkzeug.exceptions import HTTPException, NotFound, BadRequest
from jinja2 import Environment, FileSystemLoader
from shared_submit_interface import database

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
            R("/",                    self.ui_home),
            R("/robots.txt",          self.robots_txt),
        ])
        self.allow_crawlers   = False
        self.maintenance_mode = False
        self.base_url         = f"http://{address}:{port}"
        self.db               = database.SparqlInterface()  # pylint: disable=invalid-name
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
        template      = self.jinja.get_template (template_name)
        parameters    = {
            "base_url": self.base_url,
            "path":     request.path,
        }
        return self.response (template.render({ **context, **parameters }),
                              mimetype='text/html')

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

    def ui_home (self, request):
        """Implements /."""
        return self.__render_template (request, "home.html")

    def robots_txt (self, request):
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
