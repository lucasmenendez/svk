package svk

import (
	"math/big"

	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	stdgroth16 "github.com/consensys/gnark/std/recursion/groth16"
)

func nBits(bits int) *big.Int {
	// no valid number if bits <= 0
	if bits <= 0 {
		return big.NewInt(0)
	}
	// compute (1 << bits) - 1
	maxNum := big.NewInt(1)
	// left shift by 'bits'
	maxNum.Lsh(maxNum, uint(bits))
	// subtract 1 to get all bits set to 1
	return maxNum.Sub(maxNum, big.NewInt(1))
}

func compileCircuit(placeholder, assigment frontend.Circuit, outer *big.Int, field *big.Int) (constraint.ConstraintSystem, witness.Witness, groth16.Proof, groth16.VerifyingKey, error) {
	ccs, err := frontend.Compile(field, r1cs.NewBuilder, placeholder)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	fullWitness, err := frontend.NewWitness(assigment, field)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	proof, err := groth16.Prove(ccs, pk, fullWitness, stdgroth16.GetNativeProverOptions(outer, field))
	if err != nil {
		return nil, nil, nil, nil, err
	}
	publicWitness, err := fullWitness.Public()
	if err != nil {
		return nil, nil, nil, nil, err
	}
	if err = groth16.Verify(proof, vk, publicWitness, stdgroth16.GetNativeVerifierOptions(outer, field)); err != nil {
		return nil, nil, nil, nil, err
	}
	return ccs, publicWitness, proof, vk, nil
}
