<?php
/**
 * Simple Key System
 *   taking care of ZFS keys used in encryption
 *
 * @see https://github.com/chani/SimpleZFSKeySystem
 * @see https://blog.jeanbruenn.info/2023/11/11/encryption-of-zfs-volumes-using-a-remote-external-key-system-written-in-php/
 * @author Jean Bruenn <himself@jeanbruenn.info>
 */
include('rb-sqlite.php');
R::setup('sqlite:.data/keys.db');

$acls = [
    // ip address (source of request
    '1.2.3.4' => [
        // machine ID (cat /etc/machine-id)
        '6ff0dea9ddd14840bc152147c54a616c' => [
            // pool ID (zpool get guid pool-name)
            '10795044014893479470'
        ]
    ],
    '5.6.7.8' => [
        'dahohquo9ohquemo0oht0doh1baiphoo' => [
            '11299610818442892332'
        ]
    ]
];
$acls_monitoring = [];

# "cannot create 'ztank/encrypted': Raw key too long (expected 32)."
# https://github.com/openzfs/zfs/issues/6556
# https://arstechnica.com/gadgets/2021/06/a-quick-start-guide-to-openzfs-native-encryption/
# Keyformat can be either passphrase, hex, or raw. Passphrases must be between 8 and 512 bytes long, while both hex and raw keys must be precisely 32 bytes long.
# => ensure to use passphrase
$secret_length = 64;

define('__ROOT__', dirname(__FILE__));
if (file_exists(__ROOT__.'/acls.inc')) {
    error_log("keys.php: loading ".__ROOT__."/acls.inc", 0);
    require_once(__ROOT__.'/acls.inc');
}

$protocol = $_SERVER['SERVER_PROTOCOL'];
$ip = $_SERVER['REMOTE_ADDR'];
// filter by ua too? no, zfs itself has empty ua.
//$ua = filter_var($_SERVER['HTTP_USER_AGENT'], FILTER_FLAG_STRIP_HIGH);
if (!empty($_SERVER['HTTP_USER_AGENT'])) {
    $ua = $_SERVER['HTTP_USER_AGENT'];
} else {
    $ua = '';
}
if(!isset($acls[$ip])){
    error_log("keys.php: 403 Forbidden: IP $ip (ua: $ua)", 0);
    header($protocol.' 403 Forbidden');
    die();
} else if(!isset($acls_monitoring[$ip])){
    error_log("keys.php: 200: Monitoring IP $ip (ua: $ua)", 0);
    header($protocol.' 200 ');
    die();
} else {
    // alternate
    if (!empty($_GET['machine'])) {
        $machineID = filter_var($_GET['machine'], FILTER_SANITIZE_FULL_SPECIAL_CHARS);
    } else {
	$machineID = '';
    }
    if (!empty($_GET['guid'])) {
        $poolID = filter_var($_GET['guid'], FILTER_SANITIZE_FULL_SPECIAL_CHARS);
    } else {
	$poolID = '';
    }
    if (!empty($_GET['name'])) {
        $name = filter_var($_GET['name'], FILTER_SANITIZE_NUMBER_INT);
    } else {
	$name = '';
    }
    if(isset($acls[$ip][$machineID]) && in_array($poolID, $acls[$ip][$machineID])){
        $machine = R::findOne('machine', ' guid = ? ', [$machineID]);
        if(is_null($machine)){
            $machine = R::dispense('machine');
            $machine->guid = $machineID;
            $machine->address = $ip;
            R::store($machine);
        }

        $pool = R::findOne('pool', ' guid = ? AND machine = ? ', [$poolID, $machine->guid]);
        if(is_null($pool)){
            $pool = R::dispense('pool');
            $pool->guid = $poolID;
            $pool->machine = $machine->guid;
            R::store($pool);
        }

        $key = R::findOne('key', ' name = ? AND machine = ? AND pool = ? ', [ $name, $machine->guid, $pool->guid ]);
        if(is_null($key)){
            $keyvalue = bin2hex(openssl_random_pseudo_bytes($secret_length, $strong_result));
            if (!$strong_result) {
                error_log("keys.php: Warning! openssl_random_pseudo_bytes() did not use a cryptographically strong algorithm.", 0);
            }
            $key = R::dispense('key');
            $key->keyvalue = $keyvalue;
            $key->name = $name;
            $key->active = true;
            $key->machine = $machine->guid;
            $key->pool = $pool->guid;
            R::store($key);
        }

        if($key->active == true){
            die($key->keyvalue);
        } else {
            error_log("keys.php: 403 Forbidden: key not active for IP $ip, machine-id $machineID, pool $poolID, name $name (ua: $ua)", 0);
            header($protocol.' 403 Forbidden');
            die();
        }
    } else {
        error_log("keys.php: 403 Forbidden: not matching acls for IP $ip, machine-id $machineID, pool $poolID, name $name (ua: $ua)", 0);
        header($protocol.' 403 Forbidden');
        die();
    }
}
