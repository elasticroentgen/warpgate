import requests
from uuid import uuid4

from .api_client import admin_client, sdk
from .conftest import ProcessManager
from .test_http_common import *  # noqa
from .test_http_user_auth_oidc import _create_echo_target, _resolve_hosts_to_localhost
from .util import alloc_port, wait_port


def _session_set_cookie(response):
    return next(
        c
        for c in response.raw.headers.getlist("Set-Cookie")
        if c.startswith("warpgate-http-session=")
    )


class TestHTTPDomainRebinding:
    def test_session_on_target_domain_outside_external_host(
        self,
        echo_server_port,
        processes: ProcessManager,
    ):
        """A target bound to a domain that is not a subdomain of `external_host`
        keeps its session, with a host-only Secure/SameSite=None cookie, while an
        unbound foreign domain is still refused."""
        wg = processes.start_wg(
            http_port=alloc_port(),
            config_patch={"external_host": "warpgate.acme.inc"},
        )
        wait_port(wg.http_port, for_process=wg.process, recv=False)

        bound_url = f"https://app.other.inc:{wg.http_port}"
        unbound_url = f"https://unbound.other.inc:{wg.http_port}"

        with _resolve_hosts_to_localhost(
            "warpgate.acme.inc", "app.other.inc", "unbound.other.inc"
        ):
            with admin_client(f"https://warpgate.acme.inc:{wg.http_port}") as api:
                role = api.create_role(sdk.RoleDataRequest(name=f"role-{uuid4()}"))
                target = _create_echo_target(
                    api, echo_server_port, role.id, external_host="app.other.inc"
                )
                user = api.create_user(sdk.CreateUserRequest(username=f"user-{uuid4()}"))
                api.create_password_credential(
                    user.id, sdk.NewPasswordCredential(password="123")
                )
                api.add_user_role(user.id, role.id)

            session = requests.Session()
            session.verify = False
            response = session.post(
                f"{bound_url}/@warpgate/api/auth/login",
                json={"username": user.username, "password": "123"},
            )
            assert response.status_code // 100 == 2
            cookie = _session_set_cookie(response)
            assert "Domain=" not in cookie
            assert "SameSite=None" in cookie
            assert "Secure" in cookie

            # Host-based rebinding: no `warpgate-target` needed
            response = session.get(f"{bound_url}/some/path", allow_redirects=False)
            assert response.status_code // 100 == 2
            assert response.json()["path"] == "/some/path"

            session = requests.Session()
            session.verify = False
            response = session.post(
                f"{unbound_url}/@warpgate/api/auth/login",
                json={"username": user.username, "password": "123"},
            )
            assert response.status_code // 100 == 2
            response = session.get(
                f"{unbound_url}/some/path?warpgate-target={target.name}",
                allow_redirects=False,
            )
            assert response.status_code // 100 != 2
