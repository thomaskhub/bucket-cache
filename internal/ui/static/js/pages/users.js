// Users: create, disable, reset password or TOTP (FR-60, FR-64). Admin only.
YP.page({ id: 'users', title: 'Users', role: 'admin', order: 50 }, function () {
  return {
    users: [], loading: true, error: '', formError: '', busy: false,
    username: '', role: 'user',
    // one-time password shown once: {username, password}
    secret: null,
    confirming: '',

    init: function () { this.load(); },
    load: function () {
      var self = this;
      YP.api('GET', '/users').then(function (r) {
        self.loading = false;
        if (r.ok) { self.users = r.data.users || []; self.error = ''; } else self.error = r.data.error || 'Could not load users.';
      });
    },
    create: function () {
      var self = this;
      self.busy = true;
      self.formError = '';
      YP.api('POST', '/users', { username: self.username.trim(), role: self.role }).then(function (r) {
        self.busy = false;
        if (!r.ok) { self.formError = r.data.error || 'Could not create the user.'; return; }
        self.secret = { username: r.data.user.username, password: r.data.password, what: 'created' };
        self.username = '';
        self.load();
      });
    },
    dismiss: function () { this.secret = null; },
    isSelf: function (u) { return u.id === window.Alpine.store('app').session.user.id; },
    status: function (u) {
      if (u.disabled_at) return 'disabled';
      if (u.locked) return 'locked';
      if (!u.totp_enrolled) return 'not enrolled';
      if (u.must_change_password) return 'password change pending';
      return 'active';
    },
    statusClass: function (u) {
      var s = this.status(u);
      return s === 'active' ? 'badge badge-ok' : s === 'disabled' || s === 'locked' ? 'badge badge-error' : 'badge';
    },
    // confirm runs action on the second click on the same button.
    confirmLabel: function (u, action, label) {
      return this.confirming === u.id + ':' + action ? 'Confirm?' : label;
    },
    ask: function (u, action) {
      var k = u.id + ':' + action;
      if (this.confirming !== k) { this.confirming = k; return false; }
      this.confirming = '';
      return true;
    },
    done: function (r, msg) {
      if (!r.ok) this.error = r.data.error || msg;
      else this.error = '';
      this.load();
    },
    toggleDisabled: function (u) {
      if (!this.ask(u, 'disable')) return;
      var self = this;
      YP.api('PATCH', '/users/' + u.id, { disabled: !u.disabled_at }).then(function (r) { self.done(r, 'Could not update the user.'); });
    },
    toggleRole: function (u) {
      if (!this.ask(u, 'role')) return;
      var self = this;
      YP.api('PATCH', '/users/' + u.id, { role: u.role === 'admin' ? 'user' : 'admin' }).then(function (r) { self.done(r, 'Could not change the role.'); });
    },
    unlock: function (u) {
      var self = this;
      YP.api('PATCH', '/users/' + u.id, { unlock: true }).then(function (r) { self.done(r, 'Could not unlock the user.'); });
    },
    resetTOTP: function (u) {
      if (!this.ask(u, 'totp')) return;
      var self = this;
      YP.api('POST', '/users/' + u.id + '/reset-totp').then(function (r) { self.done(r, 'Could not reset TOTP.'); });
    },
    resetPassword: function (u) {
      if (!this.ask(u, 'password')) return;
      var self = this;
      YP.api('POST', '/users/' + u.id + '/reset-password').then(function (r) {
        if (r.ok) self.secret = { username: u.username, password: r.data.password, what: 'reset' };
        self.done(r, 'Could not reset the password.');
      });
    },
    remove: function (u) {
      if (!this.ask(u, 'delete')) return;
      var self = this;
      YP.api('DELETE', '/users/' + u.id).then(function (r) { self.done(r, 'Could not delete the user.'); });
    },
    disableLabel: function (u) { return this.confirmLabel(u, 'disable', u.disabled_at ? 'Enable' : 'Disable'); },
    roleLabel: function (u) { return this.confirmLabel(u, 'role', u.role === 'admin' ? 'Make user' : 'Make admin'); },
    fmt: function (iso) { return YP.fmtTime(iso); },
  };
});
