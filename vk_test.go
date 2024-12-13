package svk

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	bls12377mimc "github.com/consensys/gnark-crypto/ecc/bls12-377/fr/mimc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/algebra/native/sw_bls12377"
	"github.com/consensys/gnark/std/hash/mimc"
	"github.com/consensys/gnark/std/math/bits"
	stdgroth16 "github.com/consensys/gnark/std/recursion/groth16"
	"github.com/consensys/gnark/test"
	qt "github.com/frankban/quicktest"
)

type MainCircuit struct {
	Preimage frontend.Variable `gnark:",secret"`
	Hash     frontend.Variable `gnark:",public"`
}

func (c *MainCircuit) Define(api frontend.API) error {
	hFn, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}
	hFn.Write(c.Preimage)
	api.AssertIsEqual(c.Hash, hFn.Sum())
	return nil
}

type DummyCircuit struct {
	A frontend.Variable `gnark:",public"`
}

func (c *DummyCircuit) Define(api frontend.API) error {
	return nil
}

type OuterCircuit struct {
	Selector        frontend.Variable
	Proofs          [2]stdgroth16.Proof[sw_bls12377.G1Affine, sw_bls12377.G2Affine]
	PublicInputs    [2]stdgroth16.Witness[sw_bls12377.ScalarField]
	VerificationKey VerifiyingAndDummyKey `gnark:"-"`
}

func (c *OuterCircuit) Define(api frontend.API) error {
	verifier, err := stdgroth16.NewVerifier[sw_bls12377.ScalarField, sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT](api)
	if err != nil {
		return err
	}
	selectors := bits.ToBinary(api, c.Selector)
	for i := 0; i < len(c.Proofs); i++ {
		vk, err := c.VerificationKey.Switch(api, selectors[i])
		if err != nil {
			return err
		}
		if err := verifier.AssertProof(vk, c.Proofs[i], c.PublicInputs[i]); err != nil {
			return err
		}
	}
	return nil
}

func TestSameCircuitsInfo(t *testing.T) {
	c := qt.New(t)

	mainCCS, err := frontend.Compile(ecc.BLS12_377.ScalarField(), r1cs.NewBuilder, &MainCircuit{})
	c.Assert(err, qt.IsNil)
	mainVk := stdgroth16.PlaceholderVerifyingKey[sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT](mainCCS)

	dummyCCS, err := frontend.Compile(ecc.BLS12_377.ScalarField(), r1cs.NewBuilder, &DummyCircuit{})
	c.Assert(err, qt.IsNil)
	dummyVk := stdgroth16.PlaceholderVerifyingKey[sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT](dummyCCS)

	c.Assert(dummyVk.G1.K, qt.HasLen, len(mainVk.G1.K))
	c.Assert(dummyVk.CommitmentKeys, qt.HasLen, len(mainVk.CommitmentKeys))
	c.Assert(dummyVk.PublicAndCommitmentCommitted, qt.ContentEquals, mainVk.PublicAndCommitmentCommitted)

	c.Log("len(G1.K)", len(mainVk.G1.K))
	c.Log("len(CommitmentKeys)", len(mainVk.CommitmentKeys))
	c.Log("PublicAndCommitmentCommitted", mainVk.PublicAndCommitmentCommitted)
}

func TestOuterCircuit(t *testing.T) {
	c := qt.New(t)

	preimage := new(big.Int).SetInt64(42)
	hashFn := bls12377mimc.NewMiMC()
	_, err := hashFn.Write(preimage.Bytes())
	c.Assert(err, qt.IsNil)
	hash := hashFn.Sum(nil)

	mainCCS, mainPubWitness, mainProof, mainVk, err := compileCircuit(&MainCircuit{}, &MainCircuit{preimage, hash}, ecc.BW6_761.ScalarField(), ecc.BLS12_377.ScalarField())
	c.Assert(err, qt.IsNil)
	mainPubInputsPlaceholder := stdgroth16.PlaceholderWitness[sw_bls12377.ScalarField](mainCCS)
	mainProofPlaceholder := stdgroth16.PlaceholderProof[sw_bls12377.G1Affine, sw_bls12377.G2Affine](mainCCS)
	finalMainPubWitness, err := stdgroth16.ValueOfWitness[sw_bls12377.ScalarField](mainPubWitness)
	c.Assert(err, qt.IsNil)
	finalMainProof, err := stdgroth16.ValueOfProof[sw_bls12377.G1Affine, sw_bls12377.G2Affine](mainProof)
	c.Assert(err, qt.IsNil)
	fixedMainVk, err := stdgroth16.ValueOfVerifyingKeyFixed[sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT](mainVk)
	c.Assert(err, qt.IsNil)

	dummyCCS, dummyPubWitness, dummyProof, dummyVk, err := compileCircuit(&DummyCircuit{}, &DummyCircuit{A: 1}, ecc.BW6_761.ScalarField(), ecc.BLS12_377.ScalarField())
	c.Assert(err, qt.IsNil)
	dummyPubInputsPlaceholder := stdgroth16.PlaceholderWitness[sw_bls12377.ScalarField](dummyCCS)
	dummyProofPlaceholder := stdgroth16.PlaceholderProof[sw_bls12377.G1Affine, sw_bls12377.G2Affine](dummyCCS)
	finalDummyPubWitness, err := stdgroth16.ValueOfWitness[sw_bls12377.ScalarField](dummyPubWitness)
	c.Assert(err, qt.IsNil)
	finalDummyProof, err := stdgroth16.ValueOfProof[sw_bls12377.G1Affine, sw_bls12377.G2Affine](dummyProof)
	c.Assert(err, qt.IsNil)
	fixedDummyVk, err := stdgroth16.ValueOfVerifyingKeyFixed[sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT](dummyVk)
	c.Assert(err, qt.IsNil)

	outerPlaceholder := OuterCircuit{
		Proofs:       [2]stdgroth16.Proof[sw_bls12377.G1Affine, sw_bls12377.G2Affine]{mainProofPlaceholder, dummyProofPlaceholder},
		PublicInputs: [2]stdgroth16.Witness[sw_bls12377.ScalarField]{mainPubInputsPlaceholder, dummyPubInputsPlaceholder},
		VerificationKey: VerifiyingAndDummyKey{
			Vk:    fixedMainVk,
			Dummy: fixedDummyVk,
		},
	}
	outerAssigment := OuterCircuit{
		Selector:     nBits(1),
		Proofs:       [2]stdgroth16.Proof[sw_bls12377.G1Affine, sw_bls12377.G2Affine]{finalMainProof, finalDummyProof},
		PublicInputs: [2]stdgroth16.Witness[sw_bls12377.ScalarField]{finalMainPubWitness, finalDummyPubWitness},
	}

	assert := test.NewAssert(t)
	assert.SolvingSucceeded(&outerPlaceholder, &outerAssigment,
		test.WithCurves(ecc.BW6_761), test.WithBackends(backend.GROTH16),
		test.WithProverOpts(stdgroth16.GetNativeProverOptions(ecc.BN254.ScalarField(), ecc.BW6_761.ScalarField())))
}
