// Repositories: the git mirrors (FR-92) from the M5 admin API. Hidden when
// no git remotes are configured (the session lists them in git_remotes).
YP.page({
  id: 'repos', title: 'Repositories', role: 'user', order: 35,
  visible: function (s) { return !!s && (s.git_remotes || []).length > 0; },
}, function () {
  return {
    repos: [], remotes: [], loading: true, error: '', notice: '',
    busy: '', confirming: '',
    // admin: mirror a repo now (pre-seed)
    addRemote: '', addRepo: '', addError: '',

    init: function () { this.load(); },
    load: function () {
      var self = this;
      YP.api('GET', '/repos').then(function (r) {
        self.loading = false;
        if (!r.ok) { self.error = r.data.error || 'Could not load the mirrors.'; return; }
        self.error = '';
        self.repos = r.data.repos || [];
        self.remotes = r.data.remotes || [];
        if (!self.addRemote && self.remotes.length) self.addRemote = self.remotes[0].name;
      });
    },
    isAdmin: function () { return window.Alpine.store('app').isAdmin(); },
    key: function (m) { return m.remote + '/' + m.repo; },
    path: function (m) {
      var parts = m.repo.split('/');
      return '/repos/' + encodeURIComponent(m.remote) + '/' + encodeURIComponent(parts[0]) + '/' + encodeURIComponent(parts[1]);
    },
    isBusy: function (m) { return this.busy === this.key(m); },
    refresh: function (m) {
      var self = this;
      self.busy = self.key(m);
      self.notice = '';
      YP.api('POST', self.path(m) + '/refresh').then(function (r) {
        self.busy = '';
        if (r.ok) self.notice = 'Refreshed ' + self.key(m) + '.';
        else self.error = r.data.error || 'Refresh failed.';
        self.load();
      });
    },
    deleteLabel: function (m) { return this.confirming === this.key(m) ? 'Click again to delete' : 'Delete'; },
    remove: function (m) {
      var k = this.key(m);
      if (this.confirming !== k) { this.confirming = k; return; }
      this.confirming = '';
      var self = this;
      self.busy = k;
      YP.api('DELETE', self.path(m)).then(function (r) {
        self.busy = '';
        if (r.ok) self.notice = 'Deleted the mirror of ' + k + '. It is cloned again on next use.';
        else self.error = r.data.error || 'Could not delete the mirror.';
        self.load();
      });
    },
    add: function () {
      var repo = this.addRepo.trim().replace(/\.git$/, '');
      if (repo.split('/').length !== 2) { this.addError = 'Enter the repository as owner/repo.'; return; }
      var self = this;
      self.addError = '';
      self.busy = 'add';
      self.refresh0({ remote: self.addRemote, repo: repo }, function (r) {
        self.busy = '';
        if (r.ok) { self.addRepo = ''; self.notice = 'Mirrored ' + self.addRemote + '/' + repo + '.'; } else self.addError = r.data.error || 'Could not mirror the repository.';
        self.load();
      });
    },
    refresh0: function (m, done) { YP.api('POST', this.path(m) + '/refresh').then(done); },
    adding: function () { return this.busy === 'add'; },

    status: function (m) {
      if (m.stale) return 'stale';
      if (m.last_error) return 'error';
      return 'ok';
    },
    statusClass: function (m) { return this.status(m) === 'ok' ? 'badge badge-ok' : 'badge badge-error'; },
    errorText: function (m) { return m.last_error ? m.last_error + ' (' + YP.fmtTime(m.last_error_at) + ')' : ''; },
    // gitConfig returns copy-paste insteadOf lines for one remote.
    gitConfig: function (rm) {
      if (!rm.proxy_url) return '';
      var p = rm.proxy_url.replace(/^(https?:\/\/)/, '$1git:${YPROXY_TOKEN}@');
      var up = rm.url.replace(/\/*$/, '/');
      var host = up.replace(/^https?:\/\//, '').replace(/\/.*$/, '').replace(/:\d+$/, '');
      return 'P="' + p + '"\n' +
        'git config --global url."$P".insteadOf "' + up + '"\n' +
        'git config --global --add url."$P".insteadOf "git@' + host + ':"\n' +
        'git config --global --add url."$P".insteadOf "ssh://git@' + host + '/"';
    },
    fmt: function (iso) { return YP.fmtTime(iso); },
    bytes: function (n) { return YP.fmtBytes(n); },
  };
});
