// API keys for CI and admins (FR-30, FR-31). Admin only.
YP.page({ id: 'apikeys', title: 'API keys', role: 'admin', order: 30 }, function () {
  return {
    keys: [], buckets: [], loading: true, error: '', formError: '', busy: false,
    name: '', role: 'token-issuer', selBuckets: [], maxTTL: '', created: null, confirming: '',

    init: function () {
      var self = this;
      YP.api('GET', '/buckets').then(function (r) {
        if (r.ok) self.buckets = (r.data.buckets || []).map(function (b) { return b.alias; });
      });
      this.load();
    },
    load: function () {
      var self = this;
      YP.api('GET', '/apikeys').then(function (r) {
        self.loading = false;
        if (r.ok) { self.keys = r.data.apikeys || []; self.error = ''; } else self.error = r.data.error || 'Could not load API keys.';
      });
    },
    isIssuer: function () { return this.role === 'token-issuer'; },
    create: function () {
      var self = this;
      var body = { name: self.name, role: self.role };
      if (self.role === 'token-issuer') {
        body.ceiling = { scope: { buckets: self.selBuckets.slice() }, max_ttl: self.maxTTL.trim() };
      }
      self.busy = true;
      self.formError = '';
      YP.api('POST', '/apikeys', body).then(function (r) {
        self.busy = false;
        if (!r.ok) { self.formError = r.data.error || 'Could not create the API key.'; return; }
        self.created = r.data;
        self.name = self.maxTTL = '';
        self.selBuckets = [];
        self.load();
      });
    },
    dismiss: function () { this.created = null; },
    revokeLabel: function (k) { return this.confirming === k.id ? 'Click again to revoke' : 'Revoke'; },
    revoke: function (k) {
      if (this.confirming !== k.id) { this.confirming = k.id; return; }
      this.confirming = '';
      var self = this;
      YP.api('DELETE', '/apikeys/' + encodeURIComponent(k.id)).then(function (r) {
        if (!r.ok) { self.error = r.data.error || 'Could not revoke the API key.'; return; }
        self.load();
      });
    },
    ceiling: function (k) {
      if (!k.ceiling) return 'unlimited';
      var s = 'buckets: ' + ((k.ceiling.scope.buckets || []).join(', ') || 'none');
      if (k.ceiling.max_ttl) s += '; max ttl ' + YP.fmtDuration(k.ceiling.max_ttl / 1e9);
      return s;
    },
    fmt: function (iso) { return YP.fmtTime(iso); },
  };
});
