<?php

require_once __DIR__ . '/../vendor/autoload.php';

$pedersen = new Konstantin\Pedersen\PedersenCommitment();

$aliceKeys = $pedersen->genKeyPair();
$bobKeys = $pedersen->genKeyPair();
$transactKeys = $pedersen->genKeyPair();
$H = $pedersen->generateH();

$a = 10;
$b = 20;
$t = 5;

$Ca = $pedersen->commitTo($H, $aliceKeys->getPrivate(), $a);
$Cb = $pedersen->commitTo($H, $bobKeys->getPrivate(), $b);
$Ct = $pedersen->commitTo($H, $transactKeys->getPrivate(), $t);

var_dump($Ca);
var_dump($Cb);
var_dump($Ct);

$Caf = $pedersen->sub($Ca, $Ct);
$Cbf = $pedersen->add($Cb, $Ct);

$resultAlice = $pedersen->verify($H, $Caf, $aliceKeys->getPrivate()->sub($transactKeys->getPrivate()), $a - $t);
$resultBob = $pedersen->verify($H, $Cbf, $bobKeys->getPrivate()->add($transactKeys->getPrivate()), $b + $t);

var_dump($resultAlice); // true
var_dump($resultBob); // true