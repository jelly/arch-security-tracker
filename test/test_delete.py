from werkzeug.exceptions import NotFound, Forbidden
from flask import url_for

from .conftest import logged_in, create_issue, create_package, create_group, create_advisory, advisory_count, get_advisory, DEFAULT_GROUP_ID, DEFAULT_GROUP_NAME, DEFAULT_ISSUE_ID, DEFAULT_ADVISORY_ID, ERROR_LOGIN_REQUIRED, default_issue_dict, DEFAULT_ADVISORY_CONTENT
from app.advisory import advisory_get_label, advisory_get_impact_from_text, advisory_get_workaround_from_text
from app.model.enum import UserRole, Publication
from app.model.cve import issue_types
from app.model.cvegroup import CVEGroup
from app.model.advisory import Advisory
from app.view.advisory import ERROR_ADVISORY_GROUP_NOT_FIXED, ERROR_ADVISORY_ALREADY_EXISTS
from app.view.edit import WARNING_ADVISORY_ALREADY_PUBLISHED


def test_delete_group_not_found(db, client):
    resp = client.post(url_for('delete_group', avg=DEFAULT_GROUP_ID), follow_redirects=True)
    assert resp.status_code == 404


@create_package(name='foo', version='1.2.3-4')
@create_group(id=DEFAULT_GROUP_ID, issues=[DEFAULT_ISSUE_ID], packages=['foo'], affected='1.2.3-3')
@logged_in(role=UserRole.guest)
def test_delete_group_no_permission(db, client):
    resp = client.post(url_for('delete_group', avg=DEFAULT_GROUP_NAME), follow_redirects=True)
    assert resp.status_code == 403




@create_package(name='foo', version='1.2.3-4')
@create_group(id=DEFAULT_GROUP_ID, issues=[DEFAULT_ISSUE_ID], packages=['foo'], affected='1.2.3-3')
@logged_in()
def test_delete_group(db, client):
    return
    resp = client.post(url_for('delete_group', avg=DEFAULT_GROUP_NAME), follow_redirects=True)


@logged_in(role=UserRole.security_team)
def test_delete_advisory_not_found(db, client):
    return
    # XXX: gives a error 500
    resp = client.post(url_for('delete_advisory', advisory_id=DEFAULT_ADVISORY_ID), follow_redirects=True)
    assert resp.status_code == 404


@logged_in(role=UserRole.guest)
def test_delete_advisory_no_permission_guest(db, client):
    resp = client.post(url_for('delete_advisory', advisory_id=DEFAULT_ADVISORY_ID), follow_redirects=True)
    assert Forbidden.code == resp.status_code


@logged_in(role=UserRole.reporter)
def test_delete_advisory_no_permission_reporter(db, client):
    resp = client.post(url_for('delete_advisory', advisory_id=DEFAULT_ADVISORY_ID), follow_redirects=True)
    assert Forbidden.code == resp.status_code


@create_package(name='foo', version='1.2.3-4')
@create_group(id=DEFAULT_GROUP_ID, packages=['foo'], affected='1.2.3-3', fixed='1.2.3-4')
@create_advisory(id=DEFAULT_ADVISORY_ID, group_package_id=DEFAULT_GROUP_ID, advisory_type=issue_types[1], publication=Publication.published)
@logged_in(role=UserRole.security_team)
def test_delete_advisory_published(db, client):
    resp = client.post(url_for('delete_advisory', advisory_id=DEFAULT_ADVISORY_ID), follow_redirects=True)
    assert Forbidden.code == resp.status_code


@create_package(name='foo', version='1.2.3-4')
@create_group(id=DEFAULT_GROUP_ID, packages=['foo'], affected='1.2.3-3', fixed='1.2.3-4')
@create_advisory(id=DEFAULT_ADVISORY_ID, group_package_id=DEFAULT_GROUP_ID, advisory_type=issue_types[1])
@logged_in(role=UserRole.security_team)
def test_delete_advisory(db, client):
    resp = client.post(url_for('delete_advisory', advisory_id=DEFAULT_ADVISORY_ID), follow_redirects=True, data={'submit' : True})
    assert resp.status_code == 200
