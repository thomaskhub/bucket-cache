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
    // admin: allowlist entries added at runtime
    allowRemote: '', allowPattern: '', allowError: '', names: {},

    init: function () {
      var self = this;
      if (self.isAdmin()) {
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
      YP.api('GET', '/repos').then(function (r) {
        self.loading = false;
        if (!r.ok) { self.error = r.data.error || 'Could not load the mirrors.'; return; }
        self.error = '';
        self.repos = r.data.repos || [];
        self.remotes = r.data.remotes || [];
        if (!self.addRemote && self.remotes.length) self.addRemote = self.remotes[0].name;
        if (!self.allowRemote && self.remotes.length) self.allowRemote = self.remotes[0].name;
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
    // allowRows lists a remote's patterns: the config file's first (read-only),
    // then the ones added here.
    allowRows: function (rm) {
      var self = this;
      var rows = (rm.allow_config || []).map(function (p) { return { pattern: p, source: 'config file', removable: false }; });
      (rm.allow_extra || []).forEach(function (a) {
        rows.push({ pattern: a.pattern, source: 'added by ' + (self.names[a.created_by] || a.created_by) + ', ' + YP.fmtTime(a.created_at), removable: true });
      });
      return rows;
    },
    allowText: function (rm) { return rm.allow.length ? rm.allow.join(', ') : 'nothing yet'; },
    allowBusy: function () { return this.busy === 'allow'; },
    editable: function () { return this.remotes.some(function (rm) { return rm.allow_editable; }); },
    allow: function () {
      var self = this;
      var p = self.allowPattern.trim();
      self.allowError = '';
      self.busy = 'allow';
      YP.api('POST', '/git/remotes/' + encodeURIComponent(self.allowRemote) + '/allow', { pattern: p }).then(function (r) {
        self.busy = '';
        if (r.ok) { self.allowPattern = ''; self.notice = 'Allowed ' + r.data.pattern + '.'; } else self.allowError = r.data.error || 'Could not add the pattern.';
        self.load();
      });
    },
    disallowLabel: function (rm, p) { return this.confirming === 'allow:' + rm.name + '/' + p.pattern ? 'Click again to remove' : 'Remove'; },
    disallow: function (rm, p) {
      var k = 'allow:' + rm.name + '/' + p.pattern;
      if (this.confirming !== k) { this.confirming = k; return; }
      this.confirming = '';
      var self = this;
      self.busy = 'allow';
      YP.api('DELETE', '/git/remotes/' + encodeURIComponent(rm.name) + '/allow?pattern=' + encodeURIComponent(p.pattern)).then(function (r) {
        self.busy = '';
        if (r.ok) self.notice = 'Removed ' + p.pattern + '. Matching mirrors are no longer served.';
        else self.allowError = r.data.error || 'Could not remove the pattern.';
        self.load();
      });
    },
    // gitConfig returns copy-paste insteadOf lines for one remote. When
    // several remotes share an upstream (for example public and private
    // GitHub), the first takes the whole host and the others take only the
    // owners they allow; git uses the longest matching rule.
    gitConfig: function (rm) {
      if (!rm.proxy_url) return '';
      var p = rm.proxy_url.replace(/^(https?:\/\/)/, '$1git:${YPROXY_TOKEN}@');
      var up = rm.url.replace(/\/*$/, '/');
      var host = up.replace(/^https?:\/\//, '').replace(/\/.*$/, '').replace(/:\d+$/, '');
      var first = this.remotes.filter(function (x) { return x.url.replace(/\/*$/, '/') === up; })[0];
      var prefixes = [''];
      if (first && first.name !== rm.name) {
        prefixes = [];
        rm.allow.forEach(function (a) {
          var owner = a.split('/')[0] + '/';
          if (prefixes.indexOf(owner) < 0) prefixes.push(owner);
        });
        if (!prefixes.length) return '';
      }
      var lines = ['P="' + p + '"'];
      prefixes.forEach(function (o) {
        lines.push('git config --global url."${P}' + o + '".insteadOf "' + up + o + '"');
        lines.push('git config --global --add url."${P}' + o + '".insteadOf "git@' + host + ':' + o + '"');
        lines.push('git config --global --add url."${P}' + o + '".insteadOf "ssh://git@' + host + '/' + o + '"');
      });
      return lines.join('\n');
    },
    fmt: function (iso) { return YP.fmtTime(iso); },
    bytes: function (n) { return YP.fmtBytes(n); },
  };
});
