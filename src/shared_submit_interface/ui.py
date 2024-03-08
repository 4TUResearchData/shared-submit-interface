"""
This module contains the entry point for the program.
"""

import argparse
import signal
import sys
import logging
import os
import json

from defusedxml import ElementTree
from werkzeug.serving import run_simple
from rdflib.plugins.stores import berkeleydb
from shared_submit_interface import wsgi
from shared_submit_interface.convenience import value_or_none, add_logging_level, index_exists

# Even though we don't use these imports in 'ui', the state of
# SAML2_DEPENDENCY_LOADED is important to catch the situation
# in which this dependency is required due to the run-time configuration.
try:
    from onelogin.saml2.auth import OneLogin_Saml2_Auth  # pylint: disable=unused-import
    from onelogin.saml2.errors import OneLogin_Saml2_Error  # pylint: disable=unused-import
    SAML2_DEPENDENCY_LOADED = True
except (ImportError, ModuleNotFoundError):
    SAML2_DEPENDENCY_LOADED = False


class ConfigFileNotFound(Exception):
    """Raised when the database is not queryable."""


class UnsupportedSAMLProtocol(Exception):
    """Raised when an unsupported SAML protocol is used."""


class DependencyNotAvailable(Exception):
    """Raised when a required software dependency isn't available."""


class MissingConfigurationError(Exception):
    """Raised when a crucial piece of configuration is missing."""


def show_version ():
    """Show the program's version."""

    print("This is djehuty v0.0.1")
    sys.exit(0)


def show_help ():
    """Show a GNU-style help message."""
    print ("""This is shared-submit-interface.

Available options:
  --help               -h  Show this message.
  --version            -v  Show versioning information.
  --config-file=ARG    -c Load configuration from a file.
  --debug              -d Enable debugging.
  --dev-reload         -r Enable active reloading.
  --initialize         -i Populate the RDF store with default triples.\n""")
    sys.exit(0)


def sigint_handler (sig, frame):  # pylint: disable=unused-argument
    """Signal handler for SIGINT and SIGTERM."""
    logger = logging.getLogger(__name__)
    logger.info ("Received shutdown signal.  Goodbye!")
    sys.exit(0)


def config_value (xml_root, path, command_line=None, fallback=None, return_node=False):
    """Procedure to get the value a config item should have at run-time."""

    # Prefer command-line arguments.
    if command_line:
        return command_line

    # Read from the configuration file.
    if xml_root:
        item = xml_root.find(path)
        if item is not None:
            if return_node:
                return item
            return item.text

    # Fall back to the fallback value.
    return fallback


def read_boolean_value (xml_root, path, default_value, logger):
    """Parses a boolean option and sets DESTINATION if the option is present."""
    try:
        parsed = config_value (xml_root, path, None, None)
        if parsed is not None:
            return bool(int(parsed))
    except ValueError:
        logger.error ("Erroneous value for '%s' - assuming '%s'.", path, default_value)

    return default_value


def configure_file_logging (log_file, inside_reload, logger):
    """Procedure to set up logging to a file."""
    is_writeable = False
    log_file     = os.path.abspath (log_file)
    try:
        with open (log_file, "a", encoding = "utf-8"):
            is_writeable = True
    except (PermissionError, FileNotFoundError):
        pass

    if not is_writeable:
        if not inside_reload:
            logger.warning ("Cannot write to '%s'.", log_file)
    else:
        file_handler = logging.FileHandler (log_file, 'a')
        if not inside_reload:
            logger.info ("Writing further messages to '%s'.", log_file)

        formatter    = logging.Formatter('[%(levelname)s] %(asctime)s - %(name)s: %(message)s')
        file_handler.setFormatter(formatter)
        file_handler.setLevel(logging.INFO)
        log          = logging.getLogger()
        for handler in log.handlers[:]:
            log.removeHandler(handler)
        log.addHandler(file_handler)


def read_pre_shared_keys_for_repositories (server, xml_root, logger):
    """Procedure to read integration keys for DANS and 4TU."""

    repositories = xml_root.find("repositories")
    if not repositories:
        return None

    for repository in repositories:
        name = repository.attrib.get("name")
        api_base_url = repository.attrib.get("base-url")
        api_endpoint = repository.attrib.get("endpoint")
        pre_shared_key = repository.text
        register_repository = True
        if name is None or name == "":
            logger.error("The 'name' attribute is required for repository '%s'.", name)
            register_repository = False
        if (api_base_url is None or api_base_url == "" or
            api_endpoint is None or api_endpoint == ""):
            logger.error("The 'endpoint' attribute is required for repository '%s'.", name)
            register_repository = False
        if pre_shared_key is None or pre_shared_key == "":
            logger.error("A pre-shared key is needed for repository '%s'.", name)
            register_repository = False
        if register_repository:
            pre_shared_key = pre_shared_key.replace(" ", "").replace("\n", "").replace("\r", "").replace("\t", "")
            server.repositories[name] = { "psk": pre_shared_key, "base-url": api_base_url, "endpoint": api_endpoint }
            logger.info ("Added '%s' repository.", name)

    return None


def read_automatic_login_configuration (server, xml_root):
    """Procedure to parse and set automatic login for development setups."""
    automatic_login_email = config_value (xml_root, "authentication/automatic-login-email")
    if (automatic_login_email is not None
        and server.saml_config is None):
        server.identity_provider = "automatic-login"
        server.automatic_login_email = automatic_login_email


def read_saml_configuration (server, xml_root, logger):
    """Read the SAML configuration from XML_ROOT."""

    saml = xml_root.find("authentication/saml")
    if not saml:
        return None

    saml_version = None
    if "version" in saml.attrib:
        saml_version = saml.attrib["version"]

    if saml_version != "2.0":
        logger.error ("Only SAML 2.0 is supported.")
        raise UnsupportedSAMLProtocol

    saml_strict = bool(int(config_value (saml, "strict", None, True)))
    saml_debug  = bool(int(config_value (saml, "debug", None, False)))

    ## Service Provider settings
    service_provider     = saml.find ("service-provider")
    if service_provider is None:
        logger.error ("Missing service-provider information for SAML.")

    saml_sp_x509         = config_value (service_provider, "x509-certificate")
    saml_sp_private_key  = config_value (service_provider, "private-key")

    ## Service provider metadata
    sp_metadata          = service_provider.find ("metadata")
    if sp_metadata is None:
        logger.error ("Missing service provider's metadata for SAML.")

    organization_name    = config_value (sp_metadata, "display-name")
    organization_url     = config_value (sp_metadata, "url")

    sp_tech_contact      = sp_metadata.find ("./contact[@type='technical']")
    if sp_tech_contact is None:
        logger.error ("Missing technical contact information for SAML.")
    sp_tech_email        = config_value (sp_tech_contact, "email")
    if sp_tech_email is None:
        sp_tech_email = "-"

    sp_admin_contact     = sp_metadata.find ("./contact[@type='administrative']")
    if sp_admin_contact is None:
        logger.error ("Missing administrative contact information for SAML.")
    sp_admin_email        = config_value (sp_admin_contact, "email")
    if sp_admin_email is None:
        sp_admin_email = "-"

    sp_support_contact   = sp_metadata.find ("./contact[@type='support']")
    if sp_support_contact is None:
        logger.error ("Missing support contact information for SAML.")
    sp_support_email        = config_value (sp_support_contact, "email")
    if sp_support_email is None:
        sp_support_email = "-"

    ## Identity Provider settings
    identity_provider    = saml.find ("identity-provider")
    if identity_provider is None:
        logger.error ("Missing identity-provider information for SAML.")

    saml_idp_entity_id   = config_value (identity_provider, "entity-id")
    saml_idp_x509        = config_value (identity_provider, "x509-certificate")

    sso_service          = identity_provider.find ("single-signon-service")
    if sso_service is None:
        logger.error ("Missing SSO information of the identity-provider for SAML.")

    saml_idp_sso_url     = config_value (sso_service, "url")
    saml_idp_sso_binding = config_value (sso_service, "binding")

    server.identity_provider = "saml"

    ## Create an almost-ready-to-serialize configuration structure.
    ## The SP entityId will and ACS URL be generated at a later time.
    server.saml_config = {
        "strict": saml_strict,
        "debug":  saml_debug,
        "sp": {
            "entityId": None,
            "assertionConsumerService": {
                "url": None,
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
            },
            "singleLogoutService": {
                "url": None,
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
            },
            "NameIDFormat": "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
            "x509cert": saml_sp_x509,
            "privateKey": saml_sp_private_key
        },
        "idp": {
            "entityId": saml_idp_entity_id,
            "singleSignOnService": {
                "url": saml_idp_sso_url,
                "binding": saml_idp_sso_binding
            },
            "singleLogoutService": {
                "url": None,
                "binding": None
            },
            "x509cert": saml_idp_x509
        },
        "security": {
            "nameIdEncrypted": False,
            "authnRequestsSigned": True,
            "logoutRequestSigned": True,
            "logoutResponseSigned": True,
            "signMetadata": True,
            "wantMessagesSigned": False,
            "wantAssertionsSigned": False,
            "wantNameId" : True,
            "wantNameIdEncrypted": False,
            "wantAssertionsEncrypted": False,
            "allowSingleLabelDomains": False,
            "signatureAlgorithm": "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
            "digestAlgorithm": "http://www.w3.org/2001/04/xmlenc#sha256",
            "rejectDeprecatedAlgorithm": True
        },
        "contactPerson": {
            "technical": {
                "givenName": "Technical support",
                "emailAddress": sp_tech_email
            },
            "support": {
                "givenName": "General support",
                "emailAddress": sp_support_email
            },
            "administrative": {
                "givenName": "Administrative support",
                "emailAddress": sp_admin_email
            }
        },
        "organization": {
            "nl": {
                "name": organization_name,
                "displayname": organization_name,
                "url": organization_url
            },
            "en": {
                "name": organization_name,
                "displayname": organization_name,
                "url": organization_url
            }
        }
    }

    del saml_sp_x509
    del saml_sp_private_key
    return None


def setup_saml_service_provider (server, logger):
    """Write the SAML configuration file to disk and set up its metadata."""
    ## python3-saml wants to read its configuration from a file,
    ## but unfortunately we can only indicate the directory for that
    ## file.  Therefore, we create a separate directory in the cache
    ## for this purpose and place the file in that directory.
    if server.identity_provider == "saml":
        if not SAML2_DEPENDENCY_LOADED:
            logger.error ("Missing python3-saml dependency.")
            logger.error ("Cannot initiate authentication with SAML.")
            raise DependencyNotAvailable

        saml_cache_dir = os.path.join(server.db.cache.storage, "saml-config")
        os.makedirs (saml_cache_dir, mode=0o700, exist_ok=True)
        if os.path.isdir (saml_cache_dir):
            filename  = os.path.join (saml_cache_dir, "settings.json")
            saml_base_url = f"{server.base_url}/saml"
            saml_idp_binding = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
            # pylint: disable=unsubscriptable-object
            # PyLint assumes server.saml_config is None, but we can be certain
            # it contains a saml configuration, because otherwise
            # server.identity_provider wouldn't be set to "saml".
            server.saml_config["sp"]["entityId"] = saml_base_url
            server.saml_config["sp"]["assertionConsumerService"]["url"] = f"{saml_base_url}/login"
            server.saml_config["idp"]["singleSignOnService"]["binding"] = saml_idp_binding
            # pylint: enable=unsubscriptable-object
            config_fd = os.open (filename, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with open (config_fd, "w", encoding="utf-8") as file_stream:
                json.dump(server.saml_config, file_stream)
            server.saml_config_path = saml_cache_dir
        else:
            logger.error ("Failed to create '%s'.", saml_cache_dir)


def read_configuration_file (config, server, config_file, logger, config_files):
    """Procedure to parse a configuration file."""

    inside_reload = os.environ.get('WERKZEUG_RUN_MAIN')
    try:
        if config_file is None:
            raise FileNotFoundError

        tree = ElementTree.parse(config_file)
        if config_file is not None:
            config_files.add (config_file)
            if not inside_reload:
                logger.info ("Reading config file: %s", config_file)

        xml_root = tree.getroot()
        if xml_root.tag != "shared-submit-interface":
            raise ConfigFileNotFound

        log_file = config_value (xml_root, "log-file", None, None)
        if log_file is not None:
            config["log-file"] = log_file
            configure_file_logging (log_file, inside_reload, logger)

        address = value_or_none (config, "address")
        port    = value_or_none (config, "port")
        config["address"] = config_value (xml_root, "bind-address", address, "127.0.0.1")
        config["port"]    = int(config_value (xml_root, "port", port, 8080))

        use_reloader = value_or_none (config, "use_reloader")
        use_debugger = value_or_none (config, "use_debugger")
        config["use_reloader"]  = config_value (xml_root, "live-reload", use_reloader)
        config["use_debugger"]  = config_value (xml_root, "debug-mode", use_debugger)

        cache_root = xml_root.find ("cache-root")
        if cache_root is not None:
            server.db.cache.storage = cache_root.text
            try:
                clear_on_start = cache_root.attrib.get("clear-on-start")
                config["clear-cache-on-start"] = bool(int(clear_on_start))
            except ValueError:
                logger.warning ("Invalid value for the 'clear-on-start' attribute in 'cache-root'.")
                logger.warning ("Will not clear cache on start; Use '1' to enable, or '0' to disable.")
                config["clear-cache-on-start"] = False
            except TypeError:
                config["clear-cache-on-start"] = False
        elif server.db.cache.storage is None:
            server.db.cache.storage = f"{server.db.storage}/cache"

        production_mode = xml_root.find ("production")
        if production_mode is not None:
            server.in_production = bool(int(production_mode.text))

        enable_query_audit_log = xml_root.find ("enable-query-audit-log")
        if enable_query_audit_log is not None:
            config["transactions_directory"] = enable_query_audit_log.attrib.get("transactions-directory")
            try:
                server.db.enable_query_audit_log = bool(int(enable_query_audit_log.text))
            except (ValueError, TypeError):
                logger.info("Invalid value for enable-query-audit-log. Ignoring.. assuming 1 (True)")

        server.allow_crawlers = read_boolean_value (xml_root, "allow-crawlers",
                                                    server.allow_crawlers, logger)

        server.base_url   = config_value (xml_root, "base-url", server.base_url,
                                          f"http://{config['address']}:{config['port']}")

        endpoint = config_value (xml_root, "rdf-store/sparql-uri")
        if endpoint:
            server.db.endpoint = endpoint

        update_endpoint = config_value (xml_root, "rdf-store/sparql-update-uri")
        if update_endpoint:
            server.db.update_endpoint = update_endpoint

        read_pre_shared_keys_for_repositories (server, xml_root, logger)
        read_saml_configuration (server, xml_root, logger)
        read_automatic_login_configuration (server, xml_root)

        for include_element in xml_root.iter('include'):
            include = include_element.text
            if include is None:
                continue

            if not os.path.isabs(include):
                config_dir = os.path.dirname(config_file)
                include    = os.path.join(config_dir, include)

            new_config = read_configuration_file (config, server, include, logger, config_files)
            config = { **config, **new_config }
            return config

    except ConfigFileNotFound:
        if not inside_reload:
            logger.error ("%s does not look like a configuration file for this program.",
                          config_file)
    except ElementTree.ParseError:
        if not inside_reload:
            logger.error ("%s does not contain valid XML.", config_file)
    except FileNotFoundError as error:
        if not inside_reload:
            if config_file is None:
                logger.error ("No configuration file specified.")
            else:
                logger.error ("Could not open '%s'.", config_file)
        raise SystemExit from error
    except UnsupportedSAMLProtocol as error:
        raise SystemExit from error

    return config


def main_inner ():
    """The main entry point of the program."""

    signal.signal(signal.SIGINT, sigint_handler)
    signal.signal(signal.SIGTERM, sigint_handler)

    logging.basicConfig(format='[%(levelname)s] %(asctime)s - %(name)s: %(message)s',
                        level=logging.INFO)

    logger = logging.getLogger (__name__)
    parser = argparse.ArgumentParser(
        usage    = '\n  %(prog)s ...',
        prog     = 'shared-submit-interface',
        add_help = False)

    parser.add_argument('--help',        '-h', action='store_true')
    parser.add_argument('--version',     '-v', action='store_true')
    parser.add_argument('--config-file', '-c', type=str, default=None)
    parser.add_argument('--debug',       '-d', action='store_true')
    parser.add_argument('--dev-reload',  '-r', action='store_true')
    parser.add_argument('--initialize',  '-i', action='store_true')

    # When using PyInstaller and Nuitka, argv[0] seems to get duplicated.
    # In the case of Nuitka, relative paths are converted to absolute paths.
    # This bit de-duplicates argv[0] in these cases.
    try:
        if os.path.abspath(sys.argv[0]) == os.path.abspath(sys.argv[1]):
            sys.argv = sys.argv[1:]
    except IndexError:
        pass

    arguments = parser.parse_args()
    if arguments.help:
        show_help()
    if arguments.version:
        show_version()
    if not index_exists (sys.argv, 1):
        print("Try --help for usage options.")
        return None
    try:
        config = {}
        server = wsgi.WebUserInterfaceServer ()
        config_files = set()
        config = read_configuration_file (config, server, arguments.config_file, logger, config_files)

        if (isinstance (server.db.endpoint, str) and
            server.db.endpoint.startswith("bdb://") and
            not berkeleydb.has_bsddb):
            logger.error(("Configured a BerkeleyDB database back-end, "
                          "but BerkeleyDB is not installed on the system "
                          "or the 'berkeleydb' Python package is missing."))
            raise DependencyNotAvailable

        setup_saml_service_provider (server, logger)
        server.db.setup_sparql_endpoint ()

        if arguments.initialize:
            logger.info ("Initialization complete.")
            server.db.initialize_database (server.automatic_login_email)
            server.db.sparql.close()
            return None

        run_simple (config["address"], config["port"], server,
                    threaded=True,
                    processes=1,
                    extra_files=list(config_files),
                    use_debugger=config["use_debugger"],
                    use_reloader=config["use_reloader"])

    except (FileNotFoundError, DependencyNotAvailable, MissingConfigurationError):
        pass

    return None


def main ():
    """Wrapper to catch KeyboardInterrupts for main_inner."""
    try:
        add_logging_level ("ACCESS", logging.INFO + 5)
        add_logging_level ("STORE", logging.INFO + 4)
        main_inner ()
    except KeyboardInterrupt:
        sigint_handler (None, None)

    sys.exit(0)
