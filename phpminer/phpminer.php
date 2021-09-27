<?php

require_once './FetchClass.php';
require_once './test_phpminer.php';

class BTCMiner
{
    private $RPC_URL = "http://127.0.0.1";
    private $RPC_PORT = "8332";
    private $RPC_USER = "rafael";
    private $RPC_PASS = "961961961";
    private $startNonce;

    private $bt;


    function __construct($startNonce)
    {
        global $block_vector;
        $this->bt = $block_vector;
        $this->startNonce = $startNonce ?? 0;
    }

    public function saveBlock($block, $mined = null) {
        $filename = "block.json";
        if ($mined) {
            $filename = "mined.txt";
        }
        $file = fopen($filename, "w");
        fwrite($file, $block);
        // fclose($file);
    }

    public function saveHash($hash) {
        $filename = "hashs.json";

        $file = fopen($filename, "a");
        fwrite($file, $hash."\n");
        fclose($file);
    }

    public function readBlock() {
        $filename = "block.json";
        $file = fopen($filename, "r") or die("Erro ao ler arquivo!");
        return fread($file, filesize($filename));
    }

    ################################################################################
    # Bitcoin Daemon JSON-HTTP RPC
    ################################################################################

    private function rpc($method, $params = null)
    {
        $data = json_encode(['id' => 'json', 'method' => $method, "params" => $params]);

        $response = (new Fetch_url($this->RPC_URL, $data, $this->RPC_PORT, array($this->RPC_USER, $this->RPC_PASS)))->source;
        $response = json_decode($response, true);
        return $response['result'];
    }

    ################################################################################
    # Bitcoin Daemon RPC Call Wrappers
    ################################################################################

    public function rpc_getblocktemplate()
    {
        $savedBlock = $this->readBlock();
        if (strlen($savedBlock) > 0) {
            return json_decode($savedBlock, true);
        }
        $block_template = $this->rpc("getblocktemplate", [["rules" => ["segwit"]]]);

        $this->saveBlock(json_encode($block_template));

        return $block_template;
    }

    public function rpc_submitblock($block_submission)
    {
        return $this->rpc("submitblock", [$block_submission]);
    }

    ################################################################################
    # Representation Conversion Utility Functions
    ################################################################################

    public function int2lehex($value, $width)
    {
        switch ($width) {
            case 4:
                $value = pack('V', $value);
                break;
            case 3:
                $value = $this->pack24bit($value);
                break;
            case 1:
                $value = $this->pack8bit($value);
                break;
            case 2:
                $value = pack('v', $value);
                break;
            case 8:
                $value = pack('P', $value); //change to 8 byte
                break;
        }

        $value = bin2hex($value);
        return $value;
    }

    private function pack24bit($n)
    {
        $b3 = $n % 256;
        $b2 = $n / 256;
        $b1 = $b2 / 256;
        $b2 = $b2 % 256;
        return pack('CCC', $b3, $b2, $b1);
    }

    private function pack8bit($n)
    {
        $b3 = $n % 256;
        return pack('C', $b3);
    }


    public function int2varinthex($value)
    {

        if ($value < 0xfd) {
            $fmtvalue = $this->int2lehex($value, 1);
        } elseif ($value <= 0xffff) {
            $fmtvalue = "fd" . $this->int2lehex($value, 2);
        } elseif ($value <= 0xffffffff) {
            $fmtvalue = "fe" . $this->int2lehex($value, 4);
        } else {
            $fmtvalue = "ff" . $this->int2lehex($value, 8);
        }

        return $fmtvalue;
    }

    public function bitcoinaddress2hash160($addr)
    {
        $table = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
        $addr = str_split(strrev($addr));

        // Convert from base58 to base10
        $decimal = gmp_init(0, 10);

        foreach ($addr as $i => $c) {
            $decimal = gmp_add($decimal, gmp_mul(gmp_pow(58, $i), strrpos($table, $c)));
        }

        $decimal = gmp_strval($decimal);
        $hex = $this->bcdechex($decimal);
        $hex = str_pad($hex, 50, "0", STR_PAD_LEFT);
        $hex = substr($hex, 2);
        $hex = substr($hex, 0, -8);

        return $hex;
    }

    private function bcdechex($dec)
    {
        $hex = '';
        do {
            $last = bcmod($dec, 16);
            $hex = dechex($last) . $hex;
            $dec = bcdiv(bcsub($dec, $last), 16);
        } while ($dec > 0);
        return $hex;
    }

    ################################################################################
    # Transaction Coinbase and Hashing Functions
    ################################################################################

    public function tx_encode_coinbase_height($height)
    {
        /*
        Encode the coinbase height, as per BIP 34:
        https://github.com/bitcoin/bips/blob/master/bip-0034.mediawiki

        Arguments:
            height (int): height of the mined block

        Returns:
            string: encoded height as an ASCII hex string
        */

        $height_lenght = (int)(log($height) / log(2)) + 1;

        $width = floor(($height_lenght + 7) / 8);

        $res = bin2hex(pack('C*', $width)) . $this->int2lehex($height, $width);
        return $res;
    }

    public function tx_make_coinbase($coinbase_script, $address, $value, $height)
    {
        /*
        Create a coinbase transaction.

        Arguments:
            coinbase_script (string): arbitrary script as an ASCII hex string
            address (string): Base58 Bitcoin address
            value (int): coinbase value
            height (int): mined block height

        Returns:
            string: coinbase transaction as an ASCII hex string

        # See https://en.bitcoin.it/wiki/Transaction
        */


        $coinbase_script = $this->tx_encode_coinbase_height($height) . $coinbase_script;
        # Create a pubkey script
        # OP_DUP OP_HASH160 <len to push> <pubkey> OP_EQUALVERIFY OP_CHECKSIG
        $pubkey_script = "76" . "a9" . "14" . $this->bitcoinaddress2hash160($address) . "88" . "ac";
        $tx = "";
        # version
        $tx .= "01000000";
        # in-counter
        $tx .= "01";
        # input[0] prev hash
        $tx .= str_pad("", 64, "0");
        # input[0] prev seqnum
        $tx .= "ffffffff";
        # input[0] script len
        $tx .= $this->int2varinthex(floor(strlen($coinbase_script) / 2));
        # input[0] script
        $tx .= $coinbase_script;
        # input[0] seqnum
        $tx .= "ffffffff";
        # out-counter
        $tx .= "01";
        # output[0] value
        $tx .= $this->int2lehex($value, 8);
        # output[0] script len
        $tx .= $this->int2varinthex(floor(strlen($pubkey_script) / 2));
        # output[0] script
        $tx .= $pubkey_script;
        # lock-time
        $tx .= "00000000";
        return $tx;
    }

    public function tx_compute_hash($tx)
    {
        /*
        Compute the SHA256 double hash of a transaction.

        Arguments:
            tx (string): transaction data as an ASCII hex string

        Return:
            string: transaction hash as an ASCII hex string
        */
        // $hash = hash('sha256', pack("H*", $tx));

        $tx_hash = bin2hex(strrev(
            hex2bin(
                hash(
                    'sha256',
                    hex2bin(
                        hash(
                            'sha256',
                            hex2bin($tx)
                        )
                    )
                )
            )
        ));

        return $tx_hash;
    }

    public function tx_compute_merkle_root($tx_hashes)
    {

        # Convert list of ASCII hex transaction hashes into bytes
        $ntx_hashes = [];
        foreach ($tx_hashes as $tx_hash) {
            $ntx_hashes[] = strrev(hex2bin($tx_hash));
        }
        $tx_hashes = $ntx_hashes;


        // # Iteratively compute the merkle root hash
        while (count($tx_hashes) > 1) {
            # Duplicate last hash if the list is odd
            if (count($tx_hashes) % 2 != 0) {
                $tx_hashes[] = $tx_hashes[count($tx_hashes) - 1];
            }

            $tx_hashes_new = [];
            $count = floor(count($tx_hashes) / 2);
            for ($i = 0; $i < $count; $i++) {
                # Concatenate the next two
                $concat = array_shift($tx_hashes) . array_shift($tx_hashes);
                # Hash them
                $concat_hash = hex2bin(hash('sha256', hex2bin(hash('sha256', $concat))));
                # Add them to our working list
                $tx_hashes_new[] = $concat_hash;
            }
            $tx_hashes = $tx_hashes_new;
        }

        # Format the root in big endian ascii hex
        $tx_hash = bin2hex(strrev($tx_hashes[0]));
        return $tx_hash;
    }

    ################################################################################
    # Block Preparation Functions
    ################################################################################

    public function block_make_header($block)
    {
        /*
        Make the block header.

        Arguments:
            block (dict): block template

        Returns:
            bytes: block header
        */

        $header = '';

        # Version
        $header .= pack("V", $block['version']);
        # Previous Block Hash
        $header .= strrev(hex2bin($block['previousblockhash']));
        # Merkle Root Hash
        $header .= strrev(hex2bin($block['merkleroot']));
        # Time
        $header .= pack("V", $block['curtime']);
        # Target Bits
        $header .= strrev(hex2bin($block['bits']));
        # Nonce
        $header .= pack("V", $block['nonce']);
        return $header;
    }

    public function block_compute_raw_hash($header)
    {

        $header = strrev(
            hex2bin(
                hash('sha256',
                    hex2bin(
                        hash('sha256',
                            $header
                        )
                    )
                )
            )
        );
        return $header;
    }

    public function block_bits2target($bits)
    {
        $bits = hex2bin($bits);
        $shift = hexdec(bin2hex($bits[0])) - 3;
        $value = substr($bits, 1);

        # Shift value to the left by shift
        $target = $value . str_pad('', $shift, hex2bin("00"), STR_PAD_RIGHT);

        # Add leading zeros
        $zeros = str_pad('', (32 - strlen($target)), hex2bin("00"), STR_PAD_RIGHT);

        $target = $zeros . $target;
        return $target;
    }

    public function block_make_submit($block)
    {

        $submission = "";

        # Block header
        $submission .= bin2hex($this->block_make_header($block));
        # Number of transactions as a varint
        $submission .= $this->int2varinthex(count($block['transactions']));
        # Concatenated transactions data
        foreach ($block['transactions'] as $tx) {
            $submission .= $tx['data'];
        }

        return $submission;
    }
    ################################################################################
    # Block Miner
    ################################################################################

    public function block_mine($block_template, $coinbase_message, $extranonce_start, $address, $timeout = null, $debugnonce_start = false)
    {
        # Add an empty coinbase transaction to the block template transactions
        $coinbase_tx = [];
        array_unshift($block_template['transactions'], $coinbase_tx);

        # Add a nonce initialized to zero to the block template
        $block_template['nonce'] = 0;

        # Compute the target hash
        $target_hash = $this->block_bits2target($block_template['bits']);

        # Mark our mine start time
        $time_start = microtime(true);

        # Initialize our running average of hashes per second
        $hash_rate = 0.0;
        $hash_rate_count = 0;

        # Loop through the extranonce
        $extranonce = $extranonce_start;
        while ($extranonce <= 4294967295) {

            # Update the coinbase transaction with the new extra nonce
            $coinbase_script = $coinbase_message . $this->int2lehex($extranonce, 4);

            $coinbase_tx['data'] = $this->tx_make_coinbase($coinbase_script, $address, $block_template['coinbasevalue'], $block_template['height']);
            $coinbase_tx['hash'] = $this->tx_compute_hash($coinbase_tx['data']);
            $block_template['transactions'][0] = $coinbase_tx;

            $arr = [];
            foreach ($block_template['transactions'] as $tx) {
                $arr[] = $tx['hash'] ?? '';
            }

            # Recompute the merkle root
            $block_template['merkleroot'] = $this->tx_compute_merkle_root($arr);

            # Reform the block header
            $block_header = $this->block_make_header($block_template);

            $time_stamp = microtime(true);

            # Loop through the nonce
            $nonce = !empty($debugnonce_start) ? $debugnonce_start : 0;

            while ($nonce <= 9994967295) {

                # Update the block header with the new 32-bit nonce
                $block_header = substr($block_header, 0, -4) . pack('V', $nonce);

                # Recompute the block hash
                $block_hash = $this->block_compute_raw_hash($block_header);
                // $this->saveHash(bin2hex($block_hash));
                # Check if it the block meets the target hash
                if ($block_hash < $target_hash) {
                    $block_template['nonce'] = $nonce;
                    $block_template['hash'] = bin2hex($block_hash);
                    return [$block_template, $hash_rate, $nonce];
                }

                # Measure hash rate and check timeout
                if ($nonce > 0 && $nonce % 1048576 == 0) {
                    $hash_rate = $hash_rate + ((1048576 / (microtime(true) - $time_stamp)) - $hash_rate) / ($hash_rate_count + 1);
                    $hash_rate_count += 1;

                    $time_stamp = microtime(true);

                    # If our mine time expired, return none
                    if ($timeout and ($time_stamp - $time_start) > $timeout) {
                        return [null, $hash_rate, $nonce];
                    }
                }

                $nonce += 1;
            }
            $extranonce += 1;
        }

        # If we ran out of extra nonces, return none
        return [null, $hash_rate, $nonce];
    }

    ################################################################################
    # Standalone Bitcoin Miner, Single-threaded
    ################################################################################

    public function standalone_miner($coinbase_message, $address)
    {
        $block_template = $this->rpc_getblocktemplate();
        $nonceInitial = $this->startNonce;
        $currentNonce = $nonceInitial;
        $initialTime = date('Y-m-d H:i:s');
        while (true) {
            echo 'Mining block template, height ' . $block_template['height'] . " | ";
            $res = $this->block_mine($block_template, bin2hex($coinbase_message), 0, $address, 5, $currentNonce);
            $mined_block = $res[0];
            $hash_rate = $res[1];
            $currentNonce = $res[2];
            echo ($hash_rate / 1000.0) . " KH/s | Nonce " . $currentNonce . "\n";

            if ($mined_block) {
                echo "Solved a block! Block hash: " . $mined_block['hash'] . "\n";
                $this->saveBlock($mined_block, 'mined');
                // $submission = $this->block_make_submit($mined_block);
                //     echo "\n";
                //    print_r($submission);
                # print("Submitting:", submission, "\n")
                // $response = $this->rpc_submitblock($submission);
                // print_r($response);
                # if response is not None:
                #     print("Submission Error: {}".format(response))
                #     break
                exit;
            }
            if ($currentNonce > ($nonceInitial + 1000000000)) {
                $finalTime = date('Y-m-d H:i:s');
                echo "iniciou em: $initialTime, finalizado em $finalTime, currentNonce $currentNonce";
                exit;
            }
        }
    }
}


$bm = new BTCMiner($argv[1] ?? 0);

// print_r($bm->readBlock());

$bm->standalone_miner('Hello from vsergeev', '1QB79A754AaKfXwynBEJe6NTrnGrdWHUNF');

exit;
