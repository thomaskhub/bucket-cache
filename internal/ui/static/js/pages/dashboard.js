// Dashboard: counts and the newest active tokens (FR-60).
YP.page({ id: 'dashboard', title: 'Dashboard', role: 'user', order: 10 }, function () {
  return {
    loading: true, error: '',
    tokens: [], buckets: 0, users: null, apikeys: null,
    init: function () {
      var self = this;
      var admin = window.Alpine.store('app').isAdmin();
      var calls = [YP.api('GET', '/tokens'), YP.api('GET', '/buckets')];
      if (admin) calls.push(YP.api('GET', '/users'), YP.api('GET', '/apikeys'));
      Promise.all(calls).then(function (rs) {
        self.loading = false;
        if (!rs[0].ok) { self.error = rs[0].data.error || 'Could not load tokens.'; return; }
        self.tokens = rs[0].data.tokens || [];
        self.buckets = rs[1].ok ? (rs[1].data.buckets || []).length : 0;
        if (admin) {
          self.users = rs[2].ok ? (rs[2].data.users || []).length : null;
          self.apikeys = rs[3].ok ? (rs[3].data.apikeys || []).length : null;
        }
      });
    },
    count: function (kind) {
      return this.tokens.filter(function (t) { return t.kind === kind; }).length;
    },
    recent: function () { return this.tokens.slice(0, 5); },
    hasUsers: function () { return this.users !== null; },
    hasKeys: function () { return this.apikeys !== null; },
    fmt: function (iso) { return YP.fmtTime(iso); },
    bytes: function (n) { return YP.fmtBytes(n); },
  };
});
