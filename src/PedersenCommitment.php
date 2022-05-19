<?php

namespace Konstantin\Pedersen;

use BN\BN;
use Elliptic\EC;
use Exception;

class PedersenCommitment
{
    private EC $ec;

    public function __construct()
    {
        $this->ec = new EC('secp256k1');
    }

    /**
     *   commit to a Value X
     *   r - private Key used as blinding factor
     *   H - shared private? point on the curve
     */
    public function commitTo($H, $r, $x)
    {
        return $this->ec->g->mul($r)->add($H->mul($x));
    }

    /**
     * sum two commitments using homomorphic encryption
     */
    public function add($Cx, $Cy)
    {
        return $Cx->add($Cy);
    }

    /**
     *  subtract two commitments using homomorphic encryption
     */
    public function sub($Cx, $Cy)
    {
        return $Cx->add($Cy->neg());
    }

    /** add two known values with blinding factors
     *   and compute the committed value
     *   add rX + rY (blinding factor private keys)
     *
     *   add vX + vY (hidden values)
     */
    public function addPrivately($H, $rX, $rY, $vX, $vY)
    {
        // umod to wrap around if negative
        $rZ = $rX->add($rY)->umod($this->ec->n);
        return $this->ec->g->mul($rZ)->add($H->mul($vX + $vY));
    }

    /* subtract two known values with blinding factors
    *   and compute the committed value
    *   add rX - rY (blinding factor private keys)
    *   add vX - vY (hidden values)
    */
    public function subPrivately($H, $rX, $rY, $vX, $vY)
    {
        // umod to wrap around if negative
        $rZ = $rX->sub($rY)->umod($this->ec->n);
        return $this->ec->g->mul($rZ)->add($H->mul($vX - $vY));
    }

    /**
     * Verifies that the commitment given is the same
     *
     * @param  $H - secondary point
     * @param  $C - commitment
     * @param  $r - blinding factor private key used to create the commitment
     * @param  $v - original value committed to
     */
    public function verify($H, $C, $r, $v)
    {
        return $this->ec->g->mul($r)->add($H->mul($v))->eq($C);
    }

    /**
     * generate a random number for my curve
     * @throws Exception
     */
    public function generateRandom() : BN
    {
        do {
            $HN = new BN(bin2hex(random_bytes(32)), 'hex');
            $random = $HN;
        } while ($random->gte($this->ec->n)); // make sure it's in the safe range

        return $random;
    }

    /**
     * @throws Exception
     */
    public function generateH() {
        return $this->ec->g->mul($this->generateRandom());
    }

    public function genKeyPair() : EC\KeyPair
    {
        return $this->ec->genKeyPair();
    }
}