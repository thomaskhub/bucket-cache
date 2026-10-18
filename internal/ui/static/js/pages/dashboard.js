// Dashboard: counts, cache hit ratios, git mirrors and the newest active
// tokens (FR-60).
YP.page({ id: 'dashboard', title: 'Dashboard', role: 'user', order: 10 }, function () {
  return {
    loading: true, error: '',
    tokens: [], buckets: 0, users: null, apikeys: null,
    caches: [],    // cache stats of buckets in cache mode
    mirrors: null, // number of git mirrors, null without git
    init: function () {
      var self = this;
      var app = window.Alpine.store('app');
      var admin = app.isAdmin();
      var calls = [YP.api('GET', '/tokens'), YP.api('GET', '/buckets')];
      if (admin) calls.push(YP.api('GET', '/users'), YP.api('GET', '/apikeys'));
      Promise.all(calls).then(function (rs) {
        self.loading = false;
        if (!rs[0].ok) { self.error = rs[0].data.error || 'Could not load tokens.'; return; }
        self.tokens = rs[0].data.tokens || [];
        var buckets = rs[1].ok ? rs[1].data.buckets || [] : [];
        self.buckets = buckets.length;
        if (admin) {
          self.users = rs[2].ok ? (rs[2].data.users || []).length : null;
          self.apikeys = rs[3].ok ? (rs[3].data.apikeys || []).length : null;
        }
        var cached = buckets.filter(function (b) { return b.mode === 'cache'; });
        Promise.all(cached.map(function (b) { return YP.api('GET', '/buckets/' + encodeURIComponent(b.alias) + '/cache'); }))
          .then(function (crs) {
            self.caches = crs.filter(function (r) { return r.ok; }).map(function (r) { return r.data; });
          });
      });
      if ((app.session.git_remotes || []).length > 0) {
        YP.api('GET', '/repos').then(function (r) { if (r.ok) self.mirrors = (r.data.repos || []).length; });
      }
    },
    count: function (kind) {
      return this.tokens.filter(function (t) { return t.kind === kind; }).length;
    },
    recent: function () { return this.tokens.slice(0, 5); },
    hasUsers: function () { return this.users !== null; },
    hasKeys: function () { return this.apikeys !== null; },
    hasMirrors: function () { return this.mirrors !== null; },
    ratio: function (c) { return YP.fmtRatio(c); },
    fmt: function (iso) { return YP.fmtTime(iso); },
    bytes: function (n) { return YP.fmtBytes(n); },
  };
});
