# Test that a pg_upgrade run does not break on credcheck's password
# policies when it restores role passwords and validity dates.
#
# How pg_upgrade moves roles into the new cluster, and where credcheck
# gets in the way:
#
#   1. pg_upgrade dumps the old cluster's globals with
#      "pg_dumpall --globals-only --binary-upgrade".  For every role that
#      has a password, the dump carries the *encrypted* verifier verbatim
#      (src/bin/pg_dump/pg_dumpall.c, dumpRoles()):
#
#        SELECT pg_catalog.binary_upgrade_set_next_pg_authid_oid('16384');
#        ALTER ROLE ... PASSWORD 'SCRAM-SHA-256$4096:...';
#
#   2. pg_upgrade replays that script against the new cluster, which it
#      starts with "pg_ctl start -o '-p <port> -b ...'"
#      (src/bin/pg_upgrade/server.c), i.e. the server runs with
#      binary_upgrade = on.
#
#   3. credcheck is in shared_preload_libraries on the new cluster as well,
#      so its hooks see the ALTER ROLE ... PASSWORD '<SCRAM-SHA-256$...>'
#      statements of the restore phase.  Without special handling credcheck
#      mistakes the encrypted verifier for a plaintext password and aborts
#      the whole pg_upgrade with:
#
#        ERROR:  password type is not a plain text
#
# This test reproduces that exact step without dragging in the full
# old-cluster/new-cluster machinery of a real pg_upgrade: the restore step
# only needs a server started with -b, which is exactly how pg_upgrade
# starts the new cluster.  We build a small "old cluster" state (roles with
# encrypted verifiers and reuse history), restart the
# server in binary-upgrade mode the way pg_upgrade does, and replay the
# ALTER ROLE statements that pg_dumpall --binary-upgrade would emit.

use strict;
use warnings FATAL => 'all';

use PostgreSQL::Test::Cluster;
use PostgreSQL::Test::Utils;
use Test::More;

my $node = PostgreSQL::Test::Cluster->new('binary_upgrade');
$node->init;
$node->append_conf(
	'postgresql.conf', q{
shared_preload_libraries = 'credcheck'
credcheck.encrypted_password_allowed = off
credcheck.password_reuse_history = 3
});
$node->start;
$node->safe_psql('postgres', 'CREATE EXTENSION credcheck');

$node->safe_psql('postgres',
	q{CREATE ROLE normal_scram LOGIN PASSWORD 'Initial-Password-1!'});
$node->safe_psql('postgres',
	q{CREATE ROLE binary_scram LOGIN PASSWORD 'Initial-Password-2!'});
$node->safe_psql('postgres',
	q{CREATE ROLE binary_history LOGIN PASSWORD 'Initial-Password-3!'});

my $normal_scram = $node->safe_psql('postgres',
	q{SELECT rolpassword FROM pg_authid WHERE rolname = 'normal_scram'});
my $scram = $node->safe_psql('postgres',
	q{SELECT rolpassword FROM pg_authid WHERE rolname = 'binary_scram'});
my $history_password = $node->safe_psql('postgres',
	q{SELECT rolpassword FROM pg_authid WHERE rolname = 'binary_history'});
my $history_before = $node->safe_psql('postgres',
	q{SELECT rolename, count(*) FROM pg_password_history
	  WHERE rolename LIKE 'binary_%' GROUP BY rolename ORDER BY rolename});

# The fixture mimics a source cluster of a pg_upgrade: roles were created
# through the normal policy path, so they have encrypted SCRAM verifiers,
# and password reuse history entries.
# Sanity check for the fix: outside binary upgrade the very same statement
# (an encrypted verifier pasted into ALTER ROLE, as the pg_dumpall script
# contains it) must still be rejected -- the binary-upgrade bypass may not
# open a hole in normal operation.
my ($ret, $stdout, $stderr) = $node->psql('postgres',
	"ALTER ROLE normal_scram PASSWORD '$normal_scram'");
is($ret, 3, 'encrypted password is rejected in normal mode');
like($stderr, qr/password type is not a plain text/,
	'normal mode reports the expected error');

$node->stop;

# Cluster::start() has no extra-options parameter.  Restart the server
# with -b exactly as pg_upgrade starts the new cluster for the restore
# phase (pg_upgrade/server.c: pg_ctl start -o "-p <port> -b ..."), then
# register the postmaster pid for the usual teardown.
$ret = PostgreSQL::Test::Utils::system_log(
	'pg_ctl', '--wait',
	'--pgdata' => $node->data_dir,
	'--log' => $node->logfile,
	'--options' => '-b',
	'start');
is($ret, 0, 'server starts in binary upgrade mode');
BAIL_OUT('could not start server in binary upgrade mode') if $ret != 0;
$node->_update_pid(1);

# The statement pg_dumpall --binary-upgrade emits for a role with a SCRAM
# password.  On unfixed credcheck this is the exact point where pg_upgrade
# dies with "password type is not a plain text".
($ret, $stdout, $stderr) = $node->psql('postgres',
	"ALTER ROLE binary_scram PASSWORD '$scram'");
is($ret, 0, 'binary upgrade accepts an encrypted SCRAM verifier');
diag($stderr) if $ret != 0;

if ($ret == 0)
{
	is($node->safe_psql('postgres',
			q{SELECT rolpassword FROM pg_authid WHERE rolname = 'binary_scram'}),
		$scram, 'SCRAM verifier is restored byte-for-byte');

	# Restoring a role that has password reuse history: the replayed ALTER
	# ROLE is a *restore*, not a user password change, so it must not run
	# into the reuse policy either.
	($ret, $stdout, $stderr) = $node->psql('postgres',
		"ALTER ROLE binary_history PASSWORD '$history_password'");
	is($ret, 0, 'binary upgrade restores a role with reuse history enabled');
	diag($stderr) if $ret != 0;

	# The history store lives outside the catalog and is not carried over by
	# pg_upgrade.  The restored verifier goes through the regular credcheck
	# path, exactly as with credcheck.encrypted_password_allowed = on, so it
	# lands in the history: one new entry per restored role.
	is($history_before, "binary_history|1\nbinary_scram|1",
		'fixture has one history entry per role');
	is($node->safe_psql('postgres',
			q{SELECT rolename, count(*) FROM pg_password_history
			  WHERE rolename LIKE 'binary_%' GROUP BY rolename ORDER BY rolename}),
		"binary_history|2\nbinary_scram|2",
		'binary upgrade records restored verifiers in password history');
}

# rolvaliduntil is catalog data: the restore must reproduce it as-is,
# whatever VALID UNTIL policy the new cluster enforces for interactive
# password changes.  pg_dumpall --binary-upgrade emits CREATE ROLE
# followed by ALTER ROLE ... [VALID UNTIL ...], so replay exactly that
# pair under each policy that can rewrite or reject the dumped value.
my @valid_until_cases = (
	# [ policy GUC, VALID UNTIL clause of the dump, expected rolvaliduntil ]
	[ 'password_valid_until = 30', q{VALID UNTIL '2020-01-01 00:00:00+00'}, q{'2020-01-01 00:00:00+00'} ],
	[ 'password_valid_until = 30', '', 'NULL' ],
	[ 'password_valid_min = 30',   '', 'NULL' ],
	[ 'password_valid_max = 30',   q{VALID UNTIL 'infinity'}, q{'infinity'} ],
	[ 'password_valid_max = 30',   '', 'NULL' ],
);
my $vu = 0;
foreach my $case (@valid_until_cases)
{
	my ($guc, $clause, $expected) = @$case;
	my $role = 'binary_validity_' . ++$vu;
	my $authid = 16390 + $vu;
	# SCRAM verifiers do not embed the role name, so $scram can be reused.
	# The OID preset is what pg_dumpall --binary-upgrade emits before every
	# CREATE ROLE; without it core rejects role creation in binary upgrade
	# mode (commands/user.c: "pg_authid OID value not set ...").
	($ret, $stdout, $stderr) = $node->psql('postgres',
		"SELECT pg_catalog.binary_upgrade_set_next_pg_authid_oid('$authid');
		 SET credcheck.$guc;
		 CREATE ROLE $role;
		 ALTER ROLE $role WITH LOGIN PASSWORD '$scram' $clause");
	is($ret, 0, "binary upgrade restores $role under $guc");
	diag($stderr) if $ret != 0;
	is($node->safe_psql('postgres',
			"SELECT rolvaliduntil IS NOT DISTINCT FROM ${expected}::timestamptz
			 FROM pg_authid WHERE rolname = '$role'"),
		't', "$role keeps rolvaliduntil = $expected");
}

done_testing();
