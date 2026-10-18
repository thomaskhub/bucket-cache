// Tokens: create (CI or personal, FR-91), list and revoke (FR-20..23, FR-60).
YP.page({ id: 'tokens', title: 'Tokens', role: 'user', order: 20 }, function () {
  return {
    tokens: [], buckets: [], remotes: [], names: {},
    loading: true, error: '', formError: '', busy: false,
    // form
    kind: 'ci', description: '', selBuckets: [], prefixes: '', gitRemote: '', gitRepos: '', ttl: '',
    // the created token, shown once
    created: null,

    init: function () {
      var app = window.Alpine.store('app');
      this.remotes = app.session.git_remotes || [];
      this.gitRemote = this.remotes[0] || '';
      var self = this;
      YP.api('GET', '/buckets').then(function (r) {
        if (r.ok) self.buckets = (r.data.buckets || []).map(function (b) { return b.alias; });
      });
      if (app.isAdmin()) {
        YP.api('GET', '/users').then(function (r) {
          if (!r.ok) return;
          var m = {};
          (r.data.users || []).forEach(function (u) { m[u.id] = u.username; });
          self.names = m;
        });
      }
      this.load();
    },
    load: function () {
      var self = this;
      YP.api('GET', '/tokens').then(function (r) {
        self.loading = false;
        if (r.ok) { self.tokens = r.data.tokens || []; self.error = ''; } else self.error = r.data.error || 'Could not load tokens.';
      });
    },
    hasRemotes: function () { return this.remotes.length > 0; },
    ttlHint: function () {
      var l = window.Alpine.store('app').session.limits;
      if (this.kind === 'personal') return 'Default 30d (or the maximum), maximum ' + YP.fmtDuration(l.personal_token_max_ttl_seconds);
      return 'Default ' + YP.fmtDuration(l.token_default_ttl_seconds) + ', maximum ' + YP.fmtDuration(l.token_max_ttl_seconds);
    },
    create: function () {
      var self = this;
      var body = { kind: self.kind, description: self.description, buckets: self.selBuckets.slice() };
      var px = YP.list(self.prefixes);
      if (px.length) body.prefixes = px;
      var repos = YP.list(self.gitRepos);
      if (repos.length && self.gitRemote) body.git = [{ remote: self.gitRemote, repos: repos }];
      if (self.ttl) body.ttl = self.ttl.trim();
      self.busy = true;
      self.formError = '';
      YP.api('POST', '/tokens', body).then(function (r) {
        self.busy = false;
        if (!r.ok) { self.formError = r.data.error || 'Could not create the token.'; return; }
        self.created = r.data;
        self.description = self.prefixes = self.gitRepos = self.ttl = '';
        self.selBuckets = [];
        self.load();
      });
    },
    dismiss: function () { this.created = null; },
    envLine: function () { return this.created ? 'export SSTATE_PROXY_TOKEN=' + this.created.token : ''; },
    example: function (k) { return this.created && this.created.examples ? this.created.examples[k] || '' : ''; },
    hasExample: function (k) { return this.example(k) !== ''; },
    // revoke asks for a second click instead of a confirm() dialog.
    confirming: '',
    revokeLabel: function (t) { return this.confirming === t.id ? 'Click again to revoke' : 'Revoke'; },
    revoke: function (t) {
      if (this.confirming !== t.id) { this.confirming = t.id; return; }
      this.confirming = '';
      var self = this;
      YP.api('DELETE', '/tokens/' + encodeURIComponent(t.id)).then(function (r) {
        if (!r.ok) { self.error = r.data.error || 'Could not revoke the token.'; return; }
        self.load();
      });
    },
    scope: function (t) {
      var parts = [];
      if (t.scope.buckets && t.scope.buckets.length) parts.push('buckets: ' + t.scope.buckets.join(', '));
      if (t.scope.prefixes && t.scope.prefixes.length) parts.push('prefixes: ' + t.scope.prefixes.join(', '));
      (t.scope.git || []).forEach(function (g) { parts.push('git ' + g.remote + ': ' + g.repos.join(', ')); });
      return parts.join('; ');
    },
    creator: function (t) { return this.names[t.created_by] || t.created_by; },
    fmt: function (iso) { return YP.fmtTime(iso); },
    bytes: function (n) { return YP.fmtBytes(n); },
  };
});
