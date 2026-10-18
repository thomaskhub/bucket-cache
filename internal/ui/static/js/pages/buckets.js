// Buckets: read-only config view and connection test (FR-42, FR-60).
YP.page({ id: 'buckets', title: 'Buckets', role: 'user', order: 40 }, function () {
  return {
    buckets: [], results: {}, testing: '', loading: true, error: '',
    init: function () {
      var self = this;
      YP.api('GET', '/buckets').then(function (r) {
        self.loading = false;
        if (r.ok) self.buckets = r.data.buckets || []; else self.error = r.data.error || 'Could not load buckets.';
      });
    },
    canTest: function () { return window.Alpine.store('app').isAdmin(); },
    test: function (b) {
      var self = this;
      self.testing = b.alias;
      YP.api('POST', '/buckets/' + encodeURIComponent(b.alias) + '/test').then(function (r) {
        self.testing = '';
        var res = r.ok ? r.data : { ok: false, error: r.data.error || 'test failed' };
        var next = Object.assign({}, self.results);
        next[b.alias] = res;
        self.results = next;
      });
    },
    hasResult: function (b) { return !!this.results[b.alias]; },
    resultText: function (b) {
      var r = this.results[b.alias];
      if (!r) return '';
      return r.ok ? 'OK (' + r.latency_ms + ' ms)' : 'Failed: ' + r.error;
    },
    resultClass: function (b) {
      var r = this.results[b.alias];
      return r && r.ok ? 'badge badge-ok' : 'badge badge-error';
    },
    isTesting: function (b) { return this.testing === b.alias; },
  };
});
