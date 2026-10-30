# Test that binary upgrade can restore role passwords and validity dates
# without applying credcheck policies to the already encrypted values.

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
$node->safe_psql('postgres',
	q{CREATE ROLE binary_expiry LOGIN PASSWORD 'Initial-Password-4!'});

my $normal_scram = $node->safe_psql('postgres',
	q{SELECT rolpassword FROM pg_authid WHERE rolname = 'normal_scram'});
my $scram = $node->safe_psql('postgres',
	q{SELECT rolpassword FROM pg_authid WHERE rolname = 'binary_scram'});
my $history_password = $node->safe_psql('postgres',
	q{SELECT rolpassword FROM pg_authid WHERE rolname = 'binary_history'});
my $expiry_password = $node->safe_psql('postgres',
	q{SELECT rolpassword FROM pg_authid WHERE rolname = 'binary_expiry'});
my $history_before = $node->safe_psql('postgres',
	q{SELECT rolename, count(*) FROM pg_password_history
	  WHERE rolename LIKE 'binary_%' GROUP BY rolename ORDER BY rolename});

# The fixture itself must reject encrypted passwords outside binary upgrade.
my ($ret, $stdout, $stderr) = $node->psql('postgres',
	"ALTER ROLE normal_scram PASSWORD '$normal_scram'");
is($ret, 3, 'encrypted password is rejected in normal mode');
like($stderr, qr/password type is not a plain text/,
	'normal mode reports the expected error');

$node->stop;

# Cluster::start() has no extra-options parameter. Start with -b exactly as
# pg_upgrade does, then register the postmaster pid for the usual teardown.
$ret = PostgreSQL::Test::Utils::system_log(
	'pg_ctl', '--wait',
	'--pgdata' => $node->data_dir,
	'--log' => $node->logfile,
	'--options' => '-b',
	'start');
is($ret, 0, 'server starts in binary upgrade mode');
BAIL_OUT('could not start server in binary upgrade mode') if $ret != 0;
$node->_update_pid(1);

($ret, $stdout, $stderr) = $node->psql('postgres',
	"ALTER ROLE binary_scram PASSWORD '$scram'");
is($ret, 0, 'binary upgrade accepts an encrypted SCRAM verifier');
diag($stderr) if $ret != 0;

if ($ret == 0)
{
	is($node->safe_psql('postgres',
			q{SELECT rolpassword FROM pg_authid WHERE rolname = 'binary_scram'}),
		$scram, 'SCRAM verifier is restored byte-for-byte');

	($ret, $stdout, $stderr) = $node->psql('postgres',
		"ALTER ROLE binary_history PASSWORD '$history_password'");
	is($ret, 0, 'binary upgrade restores a role with reuse history enabled');
	diag($stderr) if $ret != 0;

	($ret, $stdout, $stderr) = $node->psql('postgres',
		"SET credcheck.password_valid_until = 30;
		 ALTER ROLE binary_expiry PASSWORD '$expiry_password'
		 VALID UNTIL '2020-01-01 00:00:00+00'");
	is($ret, 0, 'binary upgrade restores an expired VALID UNTIL value');
	diag($stderr) if $ret != 0;

	is($node->safe_psql('postgres',
			q{SELECT rolvaliduntil = '2020-01-01 00:00:00+00'::timestamptz
			  FROM pg_authid WHERE rolname = 'binary_expiry'}),
		't', 'VALID UNTIL is preserved');

	is($node->safe_psql('postgres',
			q{SELECT rolename, count(*) FROM pg_password_history
			  WHERE rolename LIKE 'binary_%' GROUP BY rolename ORDER BY rolename}),
		$history_before, 'binary upgrade does not add verifiers to password history');
}

done_testing();
