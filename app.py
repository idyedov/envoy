from __future__ import absolute_import, division, print_function, unicode_literals
from flask import Flask, Blueprint, Response, render_template, redirect, url_for, request, session, stream_with_context, jsonify, current_app
from flask_oauthlib.client import OAuth, OAuthException
from flask.ext.bootstrap import Bootstrap
import requests

main = Blueprint('main', __name__)
oauth = OAuth()
google = oauth.remote_app('google',
                          request_token_params={
                              'scope': 'https://www.googleapis.com/auth/userinfo.email'
                          },
                          base_url='https://www.googleapis.com/oauth2/v1/',
                          request_token_url=None,
                          access_token_method='POST',
                          access_token_url='https://accounts.google.com/o/oauth2/token',
                          authorize_url='https://accounts.google.com/o/oauth2/auth',
                          app_key='GOOGLE')
bootstrap = Bootstrap()

def create_proxy_view(definition):
    def _subview(path=""):
        if 'google_token' not in session:
            response = redirect('/login')
            response.set_cookie('next', path or '/')
            return response

        url = '{}{}{}{}'.format(
            definition['url'],
            '' if definition['url'].endswith('/') else '/',
            path,
            '?{}'.format(request.query_string) if request.query_string else ''
        )

        #req = requests.get(url, stream=True)
        #return Response(stream_with_context(req.iter_content()), content_type=req.headers['content-type'])

        if request.method == 'POST':
            data = request.stream.read()
            req = requests.post(url, data=data, headers={'content-type': request.headers['content-type']})
        else:
            req = requests.get(url)
        return Response(req.content, content_type=req.headers['content-type'])

    return _subview


def create_app(config_name):
    app = Flask(__name__)
    app.config.from_pyfile(config_name)

    bootstrap.init_app(app)
    oauth.init_app(app)

    if app.debug:
        from flask_debugtoolbar import DebugToolbarExtension
        DebugToolbarExtension(app)

    app.register_blueprint(main)

    methods = ['GET', 'HEAD', 'POST', 'PUT', 'OPTIONS']
    default_app_set = False
    for app_definition in app.config['APPS']:
        view = create_proxy_view(app_definition)

        if app_definition['name'] == app.config['DEFAULT_APP']:
            app.add_url_rule('/', app_definition['name'], view, methods=methods)
            app.add_url_rule('/<path:path>', app_definition['name'], view, methods=methods)
            default_app_set = True
        else:
            app.add_url_rule('/{}/'.format(app_definition['name']), app_definition['name'], view, methods=methods)
            app.add_url_rule('/{}/<path:path>'.format(app_definition['name']), app_definition['name'], view, methods=methods)

    if not default_app_set:
        def _index_subview(path=""):
            if 'google_token' not in session:
                response = redirect('/login')
                response.set_cookie('next', '/')
                return response

            me = google.get('userinfo')
            return jsonify({'data': me.data})

        app.add_url_rule('/', 'index', _index_subview)

    return app


@main.route('/login')
def login():
    callback = url_for('.authorized', _external=True)
    google_domain = current_app.config['GOOGLE_DOMAIN']
    if google_domain:
        return google.authorize(callback=callback, hd=google_domain)
    return google.authorize(callback=callback)


@main.route('/logout')
def logout():
    session.pop('google_token', None)
    return redirect('/')


@main.route('/authorized')
def authorized():
    resp = google.authorized_response()

    if resp is None:
        return 'Access denied'

    if isinstance(resp, OAuthException):
        return 'Access denied: error={} description={}'.format(
            resp.data.get('error'),
            resp.data.get('error_description')
        )

    session['google_token'] = (resp['access_token'], '')
    return redirect(request.cookies.get('next', '/'))


@google.tokengetter
def get_google_oauth_token():
    return session.get('google_token')
