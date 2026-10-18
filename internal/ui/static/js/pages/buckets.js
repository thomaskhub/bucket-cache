// Buckets: read-only config view, connection test (FR-42) and, for
// buckets in cache mode, cache stats and purging (FR-57, FR-60).
YP.page({ id: 'buckets', title: 'Buckets', role: 'user', order: 40 }, function () {
  return {
    buckets: [], results: {}, testing: '', loading: true, error: '',
    stats: {},       // alias -> GET /buckets/{alias}/cache response
    purging: '', confirmAll: '', purgeMsg: {}, purgeErr: {},

    init: function () {
      var self = this;
      YP.api('GET', '/buckets').then(function (r) {
        self.loading = false;
        if (!r.ok) { self.error = r.data.error || 'Could not load buckets.'; return; }
        self.buckets = r.data.buckets || [];
        self.loadStats();
      });
    },
    canTest: function () { return window.Alpine.store('app').isAdmin(); },
    isAdmin: function () { return window.Alpine.store('app').isAdmin(); },
    test: function (b) {
      var self = this;
      self.testing = b.alias;
      YP.api('POST', '/buckets/' + encodeURIComponent(b.alias) + '/test').then(function (r) {
        self.testing = '';
        var res = r.ok ? r.data : { ok: false, error: r.data.error || 'test failed' };
        self.results = YP.with(self.results, b.alias, res);
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

    // Cache section.
    cached: function () { return this.buckets.filter(function (b) { return b.mode === 'cache'; }); },
    hasCached: function () { return this.cached().length > 0; },
    loadStats: function () {
      var self = this;
      self.cached().forEach(function (b) {
        YP.api('GET', '/buckets/' + encodeURIComponent(b.alias) + '/cache').then(function (r) {
          self.stats = YP.with(self.stats, b.alias, r.ok ? r.data : { error: r.data.error || 'unavailable' });
        });
      });
    },
    st: function (b) { return this.stats[b.alias] || {}; },
    hasStats: function (b) { var s = this.stats[b.alias]; return !!s && !s.error; },
    statsError: function (b) { var s = this.stats[b.alias]; return s && s.error ? s.error : ''; },
    usage: function (b) {
      var s = this.st(b);
      return YP.fmtBytes(s.size) + ' of ' + YP.fmtBytes(s.max_size) + ' (' + this.usagePct(b) + '%)';
    },
    usagePct: function (b) {
      var s = this.st(b);
      return s.max_size ? Math.min(100, Math.round(100 * s.size / s.max_size)) : 0;
    },
    ratio: function (b) { return YP.fmtRatio(this.st(b)); },
    bytes: function (n) { return YP.fmtBytes(n); },

    allLabel: function (b) { return this.confirmAll === b.alias ? 'Click again to purge everything' : 'Purge whole cache'; },
    isPurging: function (b) { return this.purging === b.alias; },
    msg: function (b) { return this.purgeMsg[b.alias] || ''; },
    err: function (b) { return this.purgeErr[b.alias] || ''; },
    // purge empties the whole cache (what = ''), one key or a prefix.
    purge: function (b, what, value) {
      if (what === '' && this.confirmAll !== b.alias) { this.confirmAll = b.alias; return; }
      this.confirmAll = '';
      if (what !== '' && !(value || '').trim()) {
        this.purgeErr = YP.with(this.purgeErr, b.alias, 'Enter a ' + what + ' to purge.');
        return;
      }
      var q = what === '' ? '' : '?' + what + '=' + encodeURIComponent(value.trim());
      var self = this;
      self.purging = b.alias;
      self.purgeErr = YP.with(self.purgeErr, b.alias, '');
      YP.api('DELETE', '/buckets/' + encodeURIComponent(b.alias) + '/cache' + q).then(function (r) {
        self.purging = '';
        if (r.ok) {
          self.purgeMsg = YP.with(self.purgeMsg, b.alias, 'Removed ' + r.data.removed + ' objects (' + YP.fmtBytes(r.data.bytes_freed) + ').');
        } else {
          self.purgeErr = YP.with(self.purgeErr, b.alias, r.data.error || 'Purge failed.');
        }
        self.loadStats();
      });
    },
  };
});
