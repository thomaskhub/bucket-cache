// yproxy web UI core: API client, session handling, routing and the page
// registry. Loaded before the page scripts and Alpine itself.
//
// Alpine's CSP build can't eval, so directive expressions stay simple
// (property access, method calls, comparisons); logic lives in the
// component objects below and in js/pages/*.js.
(function () {
  'use strict';

  var pages = [];      // {id, title, role, order}
  var factories = {};  // id -> component factory

  // YP is the small global the page scripts use.
  var YP = (window.YP = {
    // page registers a page: meta {id, title, role: 'user'|'admin', order}
    // and a function returning its Alpine component.
    page: function (meta, factory) {
      pages.push({ id: meta.id, title: meta.title, role: meta.role || 'user', order: meta.order || 100 });
      factories[meta.id] = factory;
    },

    // api calls /api/v1 with the session cookie and CSRF token. It resolves
    // to {ok, status, data}; data.error holds the message on failure.
    api: function (method, path, body) {
      var app = window.Alpine.store('app');
      var opts = { method: method, credentials: 'same-origin', headers: { Accept: 'application/json' } };
      if (body !== undefined) {
        opts.headers['Content-Type'] = 'application/json';
        opts.body = JSON.stringify(body);
      }
      if (app.csrf && method !== 'GET') opts.headers['X-CSRF-Token'] = app.csrf;
      return fetch('/api/v1' + path, opts).then(function (resp) {
        return resp.text().then(function (text) {
          var data = {};
          try { data = text ? JSON.parse(text) : {}; } catch (e) { data = { error: text }; }
          if (resp.status === 401 && path !== '/session') app.loggedOut('Your session ended. Please log in again.');
          if (resp.status === 403 && data.stage) app.setStage(data.stage);
          return { ok: resp.ok, status: resp.status, data: data };
        });
      }, function () {
        return { ok: false, status: 0, data: { error: 'The proxy is not reachable.' } };
      });
    },

    // copy puts text on the clipboard. navigator.clipboard needs a secure
    // context, so plain HTTP (D7) falls back to a hidden textarea.
    copy: function (text) {
      if (navigator.clipboard && window.isSecureContext) {
        return navigator.clipboard.writeText(text).then(function () { return true; }, function () { return false; });
      }
      var ta = document.createElement('textarea');
      ta.value = text;
      ta.setAttribute('readonly', '');
      ta.className = 'sr-only';
      document.body.appendChild(ta);
      ta.select();
      var ok = false;
      try { ok = document.execCommand('copy'); } catch (e) { ok = false; }
      document.body.removeChild(ta);
      return Promise.resolve(ok);
    },

    // fmtTime formats an ISO time for tables.
    fmtTime: function (iso) {
      if (!iso) return '—';
      var d = new Date(iso);
      if (isNaN(d.getTime())) return iso;
      return d.toLocaleString(undefined, { year: 'numeric', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
    },

    // fmtDuration formats seconds as e.g. "12h" or "90d".
    fmtDuration: function (sec) {
      if (!sec) return '0';
      if (sec % 86400 === 0) return sec / 86400 + 'd';
      if (sec % 3600 === 0) return sec / 3600 + 'h';
      if (sec % 60 === 0) return sec / 60 + 'm';
      return sec + 's';
    },

    fmtBytes: function (n) {
      if (!n) return '0 B';
      var u = ['B', 'KiB', 'MiB', 'GiB', 'TiB'];
      var i = 0;
      while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
      return (i === 0 ? n : n.toFixed(1)) + ' ' + u[i];
    },

    // list splits a comma or whitespace separated input into values.
    list: function (s) {
      return (s || '').split(/[\s,]+/).filter(function (x) { return x !== ''; });
    },
  });

  function currentHash() {
    var h = (window.location.hash || '').replace(/^#\/?/, '');
    return h || 'dashboard';
  }

  document.addEventListener('alpine:init', function () {
    var Alpine = window.Alpine;

    Alpine.store('app', {
      ready: false,
      session: null,   // GET /api/v1/session response
      csrf: '',
      stage: 'login',  // login | totp_enrolment | password_change | ok
      page: currentHash(),
      notice: '',
      insecure: window.location.protocol === 'http:',

      init: function () {
        var self = this;
        window.addEventListener('hashchange', function () { self.page = currentHash(); });
        YP.api('GET', '/session').then(function (r) {
          if (r.ok) self.setSession(r.data); else self.stage = 'login';
          self.ready = true;
        });
      },

      setSession: function (s) {
        this.session = s;
        this.csrf = s.csrf_token;
        this.stage = s.stage;
        this.notice = '';
      },
      setStage: function (st) { this.stage = st; },
      loggedOut: function (msg) {
        this.session = null;
        this.csrf = '';
        this.stage = 'login';
        this.notice = msg || '';
      },
      logout: function () {
        var self = this;
        YP.api('DELETE', '/session').then(function () { self.loggedOut('You are logged out.'); });
      },

      isAdmin: function () { return !!this.session && this.session.user.role === 'admin'; },
      username: function () { return this.session ? this.session.user.username : ''; },
      role: function () { return this.session ? this.session.user.role : ''; },

      // nav lists the pages the user's role may see, in order.
      nav: function () {
        var admin = this.isAdmin();
        return pages
          .filter(function (p) { return p.role !== 'admin' || admin; })
          .sort(function (a, b) { return a.order - b.order || a.title.localeCompare(b.title); });
      },
      navClass: function (id) { return this.page === id ? 'nav-link nav-link-active' : 'nav-link'; },
      // showing reports whether page id is the current page and allowed.
      showing: function (id) {
        if (this.stage !== 'ok' || this.page !== id) return false;
        var p = pages.filter(function (x) { return x.id === id; })[0];
        return !!p && (p.role !== 'admin' || this.isAdmin());
      },
      unknownPage: function () {
        if (this.stage !== 'ok') return false;
        var id = this.page;
        return !this.nav().some(function (p) { return p.id === id; }) && id !== 'account';
      },
    });

    // Login, TOTP enrolment and password change (FR-61, FR-64).
    Alpine.data('loginForm', function () {
      return {
        username: '', password: '', code: '', error: '', busy: false,
        submit: function () {
          var self = this;
          self.busy = true;
          self.error = '';
          YP.api('POST', '/session', { username: self.username, password: self.password, code: self.code }).then(function (r) {
            self.busy = false;
            self.password = '';
            self.code = '';
            if (r.ok) Alpine.store('app').setSession(r.data);
            else self.error = r.data.error || 'Login failed.';
          });
        },
      };
    });

    Alpine.data('enrolForm', function () {
      return {
        qr: '', uri: '', secret: '', code: '', error: '', busy: false, showSecret: false,
        init: function () { this.start(); },
        start: function () {
          var self = this;
          YP.api('POST', '/session/totp').then(function (r) {
            if (r.ok) {
              self.qr = r.data.qr_png;
              self.uri = r.data.otpauth_uri;
              self.secret = r.data.secret;
            } else {
              self.error = r.data.error || 'Could not start the TOTP setup.';
            }
          });
        },
        toggleSecret: function () { this.showSecret = !this.showSecret; },
        confirm: function () {
          var self = this;
          self.busy = true;
          self.error = '';
          YP.api('POST', '/session/totp/confirm', { code: self.code }).then(function (r) {
            self.busy = false;
            self.code = '';
            if (r.ok) {
              self.qr = self.uri = self.secret = '';
              Alpine.store('app').setSession(r.data);
            } else {
              self.error = r.data.error || 'The code was not accepted.';
            }
          });
        },
      };
    });

    Alpine.data('passwordForm', function () {
      return {
        current: '', next: '', repeat: '', error: '', done: false, busy: false,
        submit: function () {
          var self = this;
          self.error = '';
          self.done = false;
          if (self.next !== self.repeat) { self.error = 'The new passwords do not match.'; return; }
          self.busy = true;
          YP.api('POST', '/session/password', { current_password: self.current, new_password: self.next }).then(function (r) {
            self.busy = false;
            self.current = self.next = self.repeat = '';
            if (r.ok) {
              self.done = true;
              Alpine.store('app').setSession(r.data);
            } else {
              self.error = r.data.error || 'The password was not changed.';
            }
          });
        },
      };
    });

    // A copy button: <button x-data="copyButton" data-copy="text" @click="copy">.
    Alpine.data('copyButton', function () {
      return {
        label: 'Copy',
        copy: function () {
          var self = this;
          YP.copy(self.$el.dataset.copy || '').then(function (ok) {
            self.label = ok ? 'Copied' : 'Copy failed';
            setTimeout(function () { self.label = 'Copy'; }, 1500);
          });
        },
      };
    });

    for (var id in factories) {
      Alpine.data('page_' + id, factories[id]);
    }
  });
})();
