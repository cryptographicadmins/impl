package mls

import (
	"testing"
	"math/rand"
	"time"
//	"sort"
//	"fmt"

//	"github.com/cisco/go-tls-syntax"
)

func BenchmarkFixedGroupsProcessTimeT_F_32_16_2(b *testing.B) {
	benchmarkFixedGroupsProcessTime(b, 32, 0)
}

func BenchmarkFixedGroupsProcessTimeF_T_32_16_2(b *testing.B) {
	benchmarkFixedGroupsProcessTime(b, 0, 16)
}

func BenchmarkFixedGroupsProcessTimeT_T_32_16_2(b *testing.B) {
	benchmarkFixedGroupsProcessTime(b, 32, 16)
}

func BenchmarkFixedGroupsProcessTimeT_F_32_16_3(b *testing.B) {
	benchmarkFixedGroupsProcessTime2(b, 32, 0)
}

func BenchmarkFixedGroupsProcessTimeF_T_32_16_3(b *testing.B) {
	benchmarkFixedGroupsProcessTime2(b, 0, 16)
}

func BenchmarkFixedGroupsProcessTimeT_T_32_16_3(b *testing.B) {
	benchmarkFixedGroupsProcessTime2(b, 32, 16)
}

func BenchmarkFixedGroupsProcessTimeT_F_32_16_4(b *testing.B) {
	benchmarkFixedGroupsProcessTime(b, 32, 0)
}

func BenchmarkFixedGroupsProcessTimeF_T_32_16_4(b *testing.B) {
	benchmarkFixedGroupsProcessTime(b, 0, 16)
}

func BenchmarkFixedGroupsProcessTimeT_T_32_16_4(b *testing.B) {
	benchmarkFixedGroupsProcessTime(b, 48, 0)
}

func benchmarkFixedGroupsProcessTime2(b *testing.B, upd, adminupd int) {
	b.StopTimer()
	G := 64
	Gstar := 16
	adminUpdaters := adminupd
	normalUpdaters := upd
	stateBench, admins := setupGroupWithRandomAdminsBench(G, Gstar)
//	fmt.Println(admins)
	admins = admins[:Gstar]
	states := stateBench.states
	adminupdates := make([]*MLSPlaintext, adminUpdaters)
	normalupdates := make([]*MLSPlaintext, normalUpdaters)

	for i := 0; i < adminUpdaters; i++ {
		index := admins[i]
		oldCred := stateBench.keyPackages[i].Credential
		newPriv, _ := oldCred.Scheme().Generate()
		newCred := NewBasicCredential(oldCred.Identity(), oldCred.Scheme(), newPriv.PublicKey)

		newKP, err := NewKeyPackageWithInitKey(suite, stateBench.keyPackages[index].InitKey, newCred, newPriv)
		if err != nil {
			panic(err)
		}

		adminupdates[i], err = states[index].AdminUpdate(&newPriv, *newKP)
	}

	var updaters []int
	if upd > 0 {
		updaters = randomSetWithout(G, admins)[:normalUpdaters]
	}

	for i := 0; i < normalUpdaters; i++ {
		index := updaters[i]
		/*
		oldCred := stateBench.keyPackages[index].Credential
		newPriv, _ := oldCred.Scheme().Generate()
		newCred := NewBasicCredential(oldCred.Identity(), oldCred.Scheme(), newPriv.PublicKey)

		newSecret := randomBytes(32)
		newInitKey, err := suite.hpke().Derive(newSecret)
		if err != nil {
			panic(err)
		}

		newKP, err := NewKeyPackageWithInitKey(suite, newInitKey.PublicKey, newCred, newPriv)

		updateSecret := randomBytes(32)
		normalupdates[i], err = states[index].Update(updateSecret, &newPriv, *newKP)

		*/
		oldCred := stateBench.keyPackages[index].Credential

		newSecret := randomBytes(32)
		newInitKey, err := suite.hpke().Derive(newSecret)

		if err != nil {
			panic(err)
		}

		newKP, err := NewKeyPackageWithInitKey(suite, newInitKey.PublicKey, &oldCred, stateBench.identityPrivs[index])
		if err != nil {
			panic(err)
		}

		normalupdates[i], err = states[index].Update(newSecret, &stateBench.identityPrivs[index], *newKP)
		if err != nil {
			panic(err)
		}
		// can maybe comment out
		/*
		_, err = states[i].Handle(normalupdates[i])
		if err != nil {
			panic(err)
		}
		*/
	}

	ind := rand.Intn(len(admins))
	state := states[admins[ind]]

	for j := 0; j < adminUpdaters; j++ {
		_, err := state.Handle(adminupdates[j])
		if err != nil {
			panic(err)
		}
	}

	for j := 0; j < normalUpdaters; j++ {
		_, err := state.Handle(normalupdates[j])
		if err != nil {
			panic(err)
		}
	}

    /*
	secret := randomBytes(32)
	com, _, _, err := state.Commit(secret)
	if err != nil {
		panic(err)
	}
    */

	nonadmins := randomSetWithout(G, admins)

	b.StartTimer()
	for i := 0; i < b.N; i++ {
		ind := rand.Intn(len(nonadmins))
		state = states[nonadmins[ind]]

		for j := 0; j < adminUpdaters; j++ {
			_, err := state.Handle(adminupdates[j])
			if err != nil {
				panic(err)
			}
		}

		for j := 0; j < normalUpdaters; j++ {
			_, err := state.Handle(normalupdates[j])
			if err != nil {
				panic(err)
			}
		}

//		 _, _ = state.Handle(com)
	}

}


type AdminStateBench struct {
	initSecrets   [][]byte
	identityPrivs []SignaturePrivateKey
	credentials   []Credential
	initPrivs     []HPKEPrivateKey
	keyPackages   []KeyPackage
	states        []AdminState
}

func setupBench(groupSize, adminSize int) AdminStateBench {
	stateBench := AdminStateBench{}
	stateBench.keyPackages = make([]KeyPackage, groupSize)
	scheme := suite.Scheme()

	for i := 0; i < groupSize; i++ {
		// cred gen
		secret := randomBytes(32)
		sigPriv, err := scheme.Derive(secret)
		if err != nil {
			panic(err)
		}

		cred := NewBasicCredential(userID, scheme, sigPriv.PublicKey)

		//kp gen
		kp, err := NewKeyPackageWithSecret(suite, secret, cred, sigPriv)
		if err != nil {
			panic(err)
		}

		// save all the materials
		stateBench.initSecrets = append(stateBench.initSecrets, secret)
		stateBench.identityPrivs = append(stateBench.identityPrivs, sigPriv)
		stateBench.credentials = append(stateBench.credentials, *cred)
		stateBench.keyPackages[i] = *kp
	}
	return stateBench
}

func setupGroupWithAdminsBench(groupSize, adminSize int) AdminStateBench {
	stateBench := setupBench(groupSize, adminSize)
	var states []AdminState
	// start with the group creator
	s0, err := NewEmptyAdminState(groupID, stateBench.initSecrets[0], stateBench.identityPrivs[0], stateBench.keyPackages[0])
	states = append(states, *s0)

	// add proposals for rest of the participants
	for i := 1; i < groupSize; i++ {
		add, err := states[0].Add(stateBench.keyPackages[i])
		if err != nil {
			panic(err)
		}
		_, err = states[0].Handle(add)
		if err != nil {
			panic(err)
		}
	}

	// commit the adds
	secret := randomBytes(32)
	_, welcome, next, err := states[0].Commit(secret)
	if err != nil {
		panic(err)
	}
	states[0] = *next
	// initialize the new joiners from the welcome
	for i := 1; i < groupSize; i++ {
		s, err := NewJoinedAdminState(stateBench.initSecrets[i], stateBench.identityPrivs[i:i+1], stateBench.keyPackages[i:i+1], *welcome)
		if err != nil {
			panic(err)
		}
		states = append(states, *s)
	}

	adminadds := make([]*MLSPlaintext, adminSize)
	for i := 1; i < adminSize; i++ {
		adminadds[i-1], err = states[0].AdminAdd(states[i].Index)
		_, err = states[0].Handle(adminadds[i-1])
	}

	// commit the adds
	secret = randomBytes(32)
	com, _, next2, err := states[0].Commit(secret)
	states[0] = *next2

	for i := 1; i < groupSize; i++ {
		for j := 1; j < adminSize; j++ {
			// Proposals
			_, err = states[i].Handle(adminadds[j-1])
		}
		// Commit
		st, err := states[i].Handle(com)
		if err != nil {
			panic(err)
		}
		states[i] = *st
	}

	stateBench.states = states

	return stateBench
}

func randomSet(groupSize int) []int {
	a := make([]int, groupSize)
	for i := range a {
		tmp := i
		a[i] = tmp
	}
	rand.Seed(time.Now().UnixNano())
	rand.Shuffle(len(a), func(i, j int) { a[i], a[j] = a[j], a[i] })
	return a
}

func randomSetNoZero(groupSize int) []int {
	a := make([]int, groupSize - 1)
	for i := 1; i < groupSize; i++ {
		tmp := i
		a[i-1] = tmp
	}
	rand.Seed(time.Now().UnixNano())
	rand.Shuffle(len(a), func(i, j int) { a[i], a[j] = a[j], a[i] })
	return a
}

func randomSetWithout(groupSize int, admins []int) []int {
	k := 0
	adminSize := len(admins)
	a := make([]int, groupSize - adminSize)
	for i := 0; i < groupSize; i++ {
		contains := false
		for j := 0; j < adminSize; j++ {
			if admins[j] == i {
				contains = true
				break
			}
		}
		if !contains {
			tmp := i
			a[k] = tmp
			k++
		}
	}
	rand.Seed(time.Now().UnixNano())
	rand.Shuffle(len(a), func(i, j int) { a[i], a[j] = a[j], a[i] })
	return a
}

func setupGroupWithRandomAdminsBench(groupSize, adminSize int) (AdminStateBench, []int) {
	stateBench := setupBench(groupSize, adminSize)
	var states []AdminState
	// start with the group creator
	s0, err := NewEmptyAdminState(groupID, stateBench.initSecrets[0], stateBench.identityPrivs[0], stateBench.keyPackages[0])
	states = append(states, *s0)

	// add proposals for rest of the participants
	for i := 1; i < groupSize; i++ {
		add, err := states[0].Add(stateBench.keyPackages[i])
		if err != nil {
			panic(err)
		}
		_, err = states[0].Handle(add)
		if err != nil {
			panic(err)
		}
	}

	// commit the adds
	secret := randomBytes(32)
	_, welcome, next, err := states[0].Commit(secret)
	if err != nil {
		panic(err)
	}
	states[0] = *next
	// initialize the new joiners from the welcome
	for i := 1; i < groupSize; i++ {
		s, err := NewJoinedAdminState(stateBench.initSecrets[i], stateBench.identityPrivs[i:i+1], stateBench.keyPackages[i:i+1], *welcome)
		if err != nil {
			panic(err)
		}
		states = append(states, *s)
	}

	admininds := randomSetNoZero(groupSize)
	admins := make([]int, adminSize)
	admins[0] = 0
	for i := 1; i < adminSize; i++ {
		admins[i] = admininds[i-1]
	}
	adminadds := make([]*MLSPlaintext, adminSize - 1)
	for i := 1; i < adminSize; i++ {
		adminadds[i-1], err = states[0].AdminAdd(states[admins[i]].Index)
		_, err = states[0].Handle(adminadds[i-1])
	}


	// commit the adds
	secret = randomBytes(32)
	com, _, next2, err := states[0].Commit(secret)
	states[0] = *next2

	for i := 1; i < groupSize; i++ {
		for j := 1; j < adminSize; j++ {
			// Proposals
			_, err = states[i].Handle(adminadds[j-1])
		}
		// Commit
		st, err := states[i].Handle(com)
		if err != nil {
			panic(err)
		}
		states[i] = *st
	}

	stateBench.states = states


	return stateBench, admins
}


/*
func TestStateUpdateAdmins(t *testing.T) {
	stateBench := setupGroupWithAdmins(t)
	states := stateBench.states
	adminupdates := make([]*MLSPlaintext, adminGroupSize)
	for i := 0; i < adminGroupSize; i++ {
		oldCred := stateBench.keyPackages[i].Credential
		newPriv, _ := oldCred.Scheme().Generate()
		newCred := NewBasicCredential(oldCred.Identity(), oldCred.Scheme(), newPriv.PublicKey)

		newSecret := randomBytes(32)
		newInitKey, err := suite.hpke().Derive(newSecret)
		require.Nil(t, err)

		newKP, err := NewKeyPackageWithInitKey(suite, newInitKey.PublicKey, newCred, newPriv)
		require.Nil(t, err)

		adminupdates[i], err = states[i].AdminUpdate(&newPriv, *newKP)
		require.Nil(t, err)
		_, err = states[i].Handle(adminupdates[i])
		require.Nil(t, err)
	}

	// commit the adds
	secret := randomBytes(32)
	com, _, next2, err := states[0].Commit(secret)
	require.Nil(t, err)
	states[0] = *next2

	for i := 1; i < totalGroupSize; i++ {
		for j := 0; j < adminGroupSize; j++ {
			// Proposals
			if i == j {
				continue
			}
			_, err = states[i].Handle(adminupdates[j])
			require.Nil(t, err)
		}
		// Commit
		st, err := states[i].Handle(com)
		require.Nil(t, err)
		states[i] = *st
	}

	stateBench.states = states

}
*/

func benchmarkAllAdminsAdminUpdateCommit(groupSize, adminSize int, b *testing.B) {
	stateBench := setupGroupWithAdminsBench(groupSize, adminSize)
	states := stateBench.states
	adminupdates := make([]*MLSPlaintext, adminSize)
	for i := 0; i < adminSize; i++ {
		oldCred := stateBench.keyPackages[i].Credential
		newPriv, _ := oldCred.Scheme().Generate()
		newCred := NewBasicCredential(oldCred.Identity(), oldCred.Scheme(), newPriv.PublicKey)

		/*
		newSecret := randomBytes(32)
		newInitKey, err := suite.hpke().Derive(newSecret)
		if err != nil {
			panic(err)
		}

		newKP, err := NewKeyPackageWithInitKey(suite, newInitKey.PublicKey, newCred, newPriv)
		*/
		newKP, err := NewKeyPackageWithInitKey(suite, stateBench.keyPackages[i].InitKey, newCred, newPriv)

		adminupdates[i], err = states[i].AdminUpdate(&newPriv, *newKP)
		if err != nil {
			panic(err)
		}
		/*
		_, err = states[0].Handle(adminupdates[i])
		if err != nil {
			panic(err)
		}
		*/
	}
	state := states[0]
	for i := 0; i < b.N; i++ {
		state = states[0]
		for j := 0; j < adminSize; j++ {
			_, err := state.Handle(adminupdates[j])
			if err != nil {
				panic(err)
			}
		}
		secret := randomBytes(32)
		_, _, _, _ = state.Commit(secret)
	}
}

func benchmarkAllAdminsNormalUpdateCommit(groupSize, adminSize int, b *testing.B) {
	stateBench := setupGroupWithAdminsBench(groupSize, adminSize)
	states := stateBench.states
	adminupdates := make([]*MLSPlaintext, adminSize)
	for i := 0; i < adminSize; i++ {
		oldCred := stateBench.keyPackages[i].Credential
		newPriv, _ := oldCred.Scheme().Generate()
		newCred := NewBasicCredential(oldCred.Identity(), oldCred.Scheme(), newPriv.PublicKey)

		newSecret := randomBytes(32)
		newInitKey, err := suite.hpke().Derive(newSecret)
		if err != nil {
			panic(err)
		}

		newKP, err := NewKeyPackageWithInitKey(suite, newInitKey.PublicKey, newCred, newPriv)

		updateSecret := randomBytes(32)
		adminupdates[i], err = states[i].Update(updateSecret, &newPriv, *newKP)
		if err != nil {
			panic(err)
		}
		/*
		_, err = states[0].Handle(adminupdates[i])
		if err != nil {
			panic(err)
		}
		*/
	}
	state := states[0]
	for i := 0; i < b.N; i++ {
		state = states[0]
		for j := 0; j < adminSize; j++ {
			_, err := state.Handle(adminupdates[j])
			if err != nil {
				panic(err)
			}
		}
		secret := randomBytes(32)
		_, _, _, _ = state.Commit(secret)
	}
}


func benchmarkAllAdminsAdminUpdateProcess(groupSize, adminSize int, b *testing.B) {
	stateBench := setupGroupWithAdminsBench(groupSize, adminSize)
	states := stateBench.states
	adminupdates := make([]*MLSPlaintext, adminSize)
	for i := 0; i < adminSize; i++ {
		oldCred := stateBench.keyPackages[i].Credential
		newPriv, _ := oldCred.Scheme().Generate()
		newCred := NewBasicCredential(oldCred.Identity(), oldCred.Scheme(), newPriv.PublicKey)

		/*
		newSecret := randomBytes(32)
		newInitKey, err := suite.hpke().Derive(newSecret)
		if err != nil {
			panic(err)
		}

		newKP, err := NewKeyPackageWithInitKey(suite, newInitKey.PublicKey, newCred, newPriv)
		*/
		newKP, err := NewKeyPackageWithInitKey(suite, stateBench.keyPackages[i].InitKey, newCred, newPriv)

		adminupdates[i], err = states[i].AdminUpdate(&newPriv, *newKP)
		_, err = states[0].Handle(adminupdates[i])
		if err != nil {
			panic(err)
		}
	}
	secret := randomBytes(32)
	com, _, _, err := states[0].Commit(secret)
	if err != nil {
		panic(err)
	}
	/*
	states[0] = *next2
	*/
	// Processing time
	state := states[1]
	for i := 0; i < b.N; i++ {
		state = states[1]
		for j := 0; j < adminSize; j++ {
			// Proposals
//			if j == 1 {
//				continue
//			}
			_, _ = state.Handle(adminupdates[j])
		}
		_, _ = state.Handle(com)
	}
}

func benchmarkAllAdminsNormalUpdateProcess(groupSize, adminSize int, b *testing.B) {
	stateBench := setupGroupWithAdminsBench(groupSize, adminSize)
	states := stateBench.states
	adminupdates := make([]*MLSPlaintext, adminSize)
	for i := 0; i < adminSize; i++ {
		oldCred := stateBench.keyPackages[i].Credential
		newPriv, _ := oldCred.Scheme().Generate()
		newCred := NewBasicCredential(oldCred.Identity(), oldCred.Scheme(), newPriv.PublicKey)

		newSecret := randomBytes(32)
		newInitKey, err := suite.hpke().Derive(newSecret)
		if err != nil { panic(err) }

		newKP, err := NewKeyPackageWithInitKey(suite, newInitKey.PublicKey, newCred, newPriv)
		normalSecret := randomBytes(32)

		adminupdates[i], err = states[i].Update(normalSecret, &newPriv, *newKP)
		_, err = states[0].Handle(adminupdates[i])
		if err != nil {
			panic(err)
		}
	}
	secret := randomBytes(32)
	com, _, _, err := states[0].Commit(secret)
	if err != nil {
		panic(err)
	}
	/*
	states[0] = *next2
	for j := 0; j < adminSize; j++ {
		// Proposals
		if j == 1 {
			continue
		}
		_, _ = states[1].Handle(adminupdates[j])
	}
	*/
	// Processing time
	for i := 0; i < b.N; i++ {
		state := states[1]
		for j := 0; j < adminSize; j++ {
			// Proposals
//			if j == 1 {
//				continue
//			}
			_, _ = state.Handle(adminupdates[j])
		}
		_, _ = state.Handle(com)
	}
}

func benchmarkAllRandomAdminsAdminUpdateCommit(groupSize, adminSize int, b *testing.B) {
	stateBench, admins := setupGroupWithRandomAdminsBench(groupSize, adminSize)
	states := stateBench.states
	adminupdates := make([]*MLSPlaintext, adminSize)
	for i := 0; i < adminSize; i++ {
		index := admins[i]
		oldCred := stateBench.keyPackages[index].Credential
		newPriv, _ := oldCred.Scheme().Generate()
		newCred := NewBasicCredential(oldCred.Identity(), oldCred.Scheme(), newPriv.PublicKey)

		/*
		newSecret := randomBytes(32)
		newInitKey, err := suite.hpke().Derive(newSecret)
		if err != nil {
			panic(err)
		}

		newKP, err := NewKeyPackageWithInitKey(suite, newInitKey.PublicKey, newCred, newPriv)
		*/
		newKP, err := NewKeyPackageWithInitKey(suite, stateBench.keyPackages[index].InitKey, newCred, newPriv)

		adminupdates[i], err = states[index].AdminUpdate(&newPriv, *newKP)
		if err != nil {
			panic(err)
		}
		/*
		_, err = states[0].Handle(adminupdates[i])
		if err != nil {
			panic(err)
		}
		*/
	}
	state := states[0]
	for i := 0; i < b.N; i++ {
		state = states[0]
		for j := 0; j < adminSize; j++ {
			_, err := state.Handle(adminupdates[j])
			if err != nil {
				panic(err)
			}
		}
		secret := randomBytes(32)
		_, _, _, _ = state.Commit(secret)
	}
}

/*
func BenchmarkAllAdminsAdminUpdateCommit8_4(b *testing.B) {
	benchmarkAllAdminsAdminUpdateCommit(8, 4, b)
}

func BenchmarkAllAdminsAdminUpdateCommit16_8(b *testing.B) {
	benchmarkAllAdminsAdminUpdateCommit(16, 8, b)
}

func BenchmarkAllAdminsAdminUpdateCommit32_16(b *testing.B) {
	benchmarkAllAdminsAdminUpdateCommit(32, 16, b)
}

func BenchmarkAllRandomAdminsAdminUpdateCommit8_4(b *testing.B) {
	benchmarkAllRandomAdminsAdminUpdateCommit(8, 4, b)
}

func BenchmarkAllRandomAdminsAdminUpdateCommit16_8(b *testing.B) {
	benchmarkAllRandomAdminsAdminUpdateCommit(16, 8, b)
}

func BenchmarkAllRandomAdminsAdminUpdateCommit32_16(b *testing.B) {
	benchmarkAllRandomAdminsAdminUpdateCommit(32, 16, b)
}

func BenchmarkAllAdminsNormalUpdateCommit8_4(b *testing.B) {
	benchmarkAllAdminsNormalUpdateCommit(8, 4, b)
}

func BenchmarkAllAdminsNormalUpdateCommit16_8(b *testing.B) {
	benchmarkAllAdminsNormalUpdateCommit(16, 8, b)
}

func BenchmarkAllAdminsNormalUpdateCommit32_16(b *testing.B) {
	benchmarkAllAdminsNormalUpdateCommit(32, 16, b)
}

func BenchmarkAllAdminsAdminUpdateProcess8_4(b *testing.B) {
	benchmarkAllAdminsAdminUpdateProcess(8, 4, b)
}

func BenchmarkAllAdminsAdminUpdateProcess16_8(b *testing.B) {
	benchmarkAllAdminsAdminUpdateProcess(16, 8, b)
}

func BenchmarkAllAdminsAdminUpdateProcess32_16(b *testing.B) {
	benchmarkAllAdminsAdminUpdateProcess(32, 16, b)
}

func BenchmarkAllAdminsNormalUpdateProcess8_4(b *testing.B) {
	benchmarkAllAdminsNormalUpdateProcess(8, 4, b)
}

func BenchmarkAllAdminsNormalUpdateProcess16_8(b *testing.B) {
	benchmarkAllAdminsNormalUpdateProcess(16, 8, b)
}

func BenchmarkAllAdminsNormalUpdateProcess32_16(b *testing.B) {
	benchmarkAllAdminsNormalUpdateProcess(32, 16, b)
}
*/

// Plot 1/3: vary |G| and |G*|; commit/process time
// Plain commit, commit + |G*|/8 admin updates, commit + |G|/4 updates, commit + |G|/4 updates + |G*|/8 admin updates
// Plot 2/4: fix |G| = 128 and |G*| = 32; commit/process time
// Plain commit, commit + 1,2,3,4,...,16 |G*| updates, commit + 2,4,6,...,32 |G| updates, commit + both
// Normal commits 
// set of admins and non-admins for updates is disjoint

// Plot 1
func benchmarkVaryGroupsCommitTime(b *testing.B, G, Gstar int, normalUpdates, adminUpdates bool) {
	b.StopTimer()
	adminUpdaters := G/8
	normalUpdaters := G/4
	stateBench, admins := setupGroupWithRandomAdminsBench(G, Gstar)
//	fmt.Println(admins)
	admins = admins[:Gstar]
	states := stateBench.states
	adminupdates := make([]*MLSPlaintext, adminUpdaters)
	normalupdates := make([]*MLSPlaintext, normalUpdaters)

	if !adminUpdates {
		adminUpdaters = 0
	}

	for i := 0; i < adminUpdaters; i++ {
		index := admins[i]
		oldCred := stateBench.keyPackages[i].Credential
		newPriv, _ := oldCred.Scheme().Generate()
		newCred := NewBasicCredential(oldCred.Identity(), oldCred.Scheme(), newPriv.PublicKey)

		newKP, err := NewKeyPackageWithInitKey(suite, stateBench.keyPackages[index].InitKey, newCred, newPriv)
		if err != nil {
			panic(err)
		}

		adminupdates[i], err = states[index].AdminUpdate(&newPriv, *newKP)
	}

	var updaters []int
	if !normalUpdates {
		normalUpdaters = 0
	} else {
		updaters = randomSetWithout(G, admins)[:normalUpdaters]
	}

	for i := 0; i < normalUpdaters; i++ {
		index := updaters[i]
		/*
		oldCred := stateBench.keyPackages[index].Credential
		newPriv, _ := oldCred.Scheme().Generate()
		newCred := NewBasicCredential(oldCred.Identity(), oldCred.Scheme(), newPriv.PublicKey)

		newSecret := randomBytes(32)
		newInitKey, err := suite.hpke().Derive(newSecret)
		if err != nil {
			panic(err)
		}

		newKP, err := NewKeyPackageWithInitKey(suite, newInitKey.PublicKey, newCred, newPriv)

		updateSecret := randomBytes(32)
		normalupdates[i], err = states[index].Update(updateSecret, &newPriv, *newKP)
		*/

		oldCred := stateBench.keyPackages[index].Credential

		newSecret := randomBytes(32)
		newInitKey, err := suite.hpke().Derive(newSecret)

		if err != nil {
			panic(err)
		}

		newKP, err := NewKeyPackageWithInitKey(suite, newInitKey.PublicKey, &oldCred, stateBench.identityPrivs[index])
		if err != nil {
			panic(err)
		}

		normalupdates[i], err = states[index].Update(newSecret, &stateBench.identityPrivs[index], *newKP)
		if err != nil {
			panic(err)
		}

		// can maybe comment out
		/*
		_, err = states[i].Handle(normalupdates[i])
		if err != nil {
			panic(err)
		}
		*/
	}

	state := states[0]
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		ind := rand.Intn(len(admins))
		state = states[admins[ind]]

		for j := 0; j < adminUpdaters; j++ {
			_, err := state.Handle(adminupdates[j])
			if err != nil {
				panic(err)
			}
		}

		for j := 0; j < normalUpdaters; j++ {
			_, err := state.Handle(normalupdates[j])
			if err != nil {
				panic(err)
			}
		}

		secret := randomBytes(32)
		_, _, _, _ = state.Commit(secret)
	}

}

func BenchmarkVaryGroupsCommitTime8_2_F_F(b *testing.B) {
	benchmarkVaryGroupsCommitTime(b, 8, 2, false, false)
}

func BenchmarkVaryGroupsCommitTime8_2_T_F(b *testing.B) {
	benchmarkVaryGroupsCommitTime(b, 8, 2, true, false)
}

func BenchmarkVaryGroupsCommitTime8_2_F_T(b *testing.B) {
	benchmarkVaryGroupsCommitTime(b, 8, 2, false, true)
}

func BenchmarkVaryGroupsCommitTime8_2_T_T(b *testing.B) {
	benchmarkVaryGroupsCommitTime(b, 8, 2, true, true)
}

func BenchmarkVaryGroupsCommitTime16_4_F_F(b *testing.B) {
	benchmarkVaryGroupsCommitTime(b, 16, 4, false, false)
}

func BenchmarkVaryGroupsCommitTime16_4_T_F(b *testing.B) {
	benchmarkVaryGroupsCommitTime(b, 16, 4, true, false)
}

func BenchmarkVaryGroupsCommitTime16_4_F_T(b *testing.B) {
	benchmarkVaryGroupsCommitTime(b, 16, 4, false, true)
}

func BenchmarkVaryGroupsCommitTime16_4_T_T(b *testing.B) {
	benchmarkVaryGroupsCommitTime(b, 16, 4, true, true)
}

func BenchmarkVaryGroupsCommitTime32_8_F_F(b *testing.B) {
	benchmarkVaryGroupsCommitTime(b, 32, 8, false, false)
}

func BenchmarkVaryGroupsCommitTime32_8_T_F(b *testing.B) {
	benchmarkVaryGroupsCommitTime(b, 32, 8, true, false)
}

func BenchmarkVaryGroupsCommitTime32_8_F_T(b *testing.B) {
	benchmarkVaryGroupsCommitTime(b, 32, 8, false, true)
}

func BenchmarkVaryGroupsCommitTime32_8_T_T(b *testing.B) {
	benchmarkVaryGroupsCommitTime(b, 32, 8, true, true)
}

func BenchmarkVaryGroupsCommitTime64_16_F_F(b *testing.B) {
	benchmarkVaryGroupsCommitTime(b, 64, 16, false, false)
}

func BenchmarkVaryGroupsCommitTime64_16_T_F(b *testing.B) {
	benchmarkVaryGroupsCommitTime(b, 64, 16, true, false)
}

func BenchmarkVaryGroupsCommitTime64_16_F_T(b *testing.B) {
	benchmarkVaryGroupsCommitTime(b, 64, 16, false, true)
}

func BenchmarkVaryGroupsCommitTime64_16_T_T(b *testing.B) {
	benchmarkVaryGroupsCommitTime(b, 64, 16, true, true)
}

func BenchmarkVaryGroupsCommitTime128_32_F_F(b *testing.B) {
	benchmarkVaryGroupsCommitTime(b, 128, 32, false, false)
}

func BenchmarkVaryGroupsCommitTime128_32_T_F(b *testing.B) {
	benchmarkVaryGroupsCommitTime(b, 128, 32, true, false)
}

func BenchmarkVaryGroupsCommitTime128_32_F_T(b *testing.B) {
	benchmarkVaryGroupsCommitTime(b, 128, 32, false, true)
}

func BenchmarkVaryGroupsCommitTime128_32_T_T(b *testing.B) {
	benchmarkVaryGroupsCommitTime(b, 128, 32, true, true)
}

/*
func BenchmarkVaryGroupsCommitTime256_64_F_F(b *testing.B) {
	benchmarkVaryGroupsCommitTime(b, 256, 64, false, false)
}

func BenchmarkVaryGroupsCommitTime256_64_T_F(b *testing.B) {
	benchmarkVaryGroupsCommitTime(b, 256, 64, true, false)
}

func BenchmarkVaryGroupsCommitTime256_64_F_T(b *testing.B) {
	benchmarkVaryGroupsCommitTime(b, 256, 64, false, true)
}

func BenchmarkVaryGroupsCommitTime256_64_T_T(b *testing.B) {
	benchmarkVaryGroupsCommitTime(b, 256, 64, true, true)
}

func BenchmarkVaryGroupsCommitTime320_80_F_F(b *testing.B) {
	benchmarkVaryGroupsCommitTime(b, 320, 80, false, false)
}

func BenchmarkVaryGroupsCommitTime320_80_T_F(b *testing.B) {
	benchmarkVaryGroupsCommitTime(b, 320, 80, true, false)
}

func BenchmarkVaryGroupsCommitTime320_80_F_T(b *testing.B) {
	benchmarkVaryGroupsCommitTime(b, 320, 80, false, true)
}

func BenchmarkVaryGroupsCommitTime320_80_T_T(b *testing.B) {
	benchmarkVaryGroupsCommitTime(b, 320, 80, true, true)
}
*/

func BenchmarkVaryGroupsProcessTime8_2_F_F(b *testing.B) {
	benchmarkVaryGroupsProcessTime(b, 8, 2, false, false)
}

func BenchmarkVaryGroupsProcessTime8_2_T_F(b *testing.B) {
	benchmarkVaryGroupsProcessTime(b, 8, 2, true, false)
}

func BenchmarkVaryGroupsProcessTime8_2_F_T(b *testing.B) {
	benchmarkVaryGroupsProcessTime(b, 8, 2, false, true)
}

func BenchmarkVaryGroupsProcessTime8_2_T_T(b *testing.B) {
	benchmarkVaryGroupsProcessTime(b, 8, 2, true, true)
}

func BenchmarkVaryGroupsProcessTime16_4_F_F(b *testing.B) {
	benchmarkVaryGroupsProcessTime(b, 16, 4, false, false)
}

func BenchmarkVaryGroupsProcessTime16_4_T_F(b *testing.B) {
	benchmarkVaryGroupsProcessTime(b, 16, 4, true, false)
}

func BenchmarkVaryGroupsProcessTime16_4_F_T(b *testing.B) {
	benchmarkVaryGroupsProcessTime(b, 16, 4, false, true)
}

func BenchmarkVaryGroupsProcessTime16_4_T_T(b *testing.B) {
	benchmarkVaryGroupsProcessTime(b, 16, 4, true, true)
}

func BenchmarkVaryGroupsProcessTime32_8_F_F(b *testing.B) {
	benchmarkVaryGroupsProcessTime(b, 32, 8, false, false)
}

func BenchmarkVaryGroupsProcessTime32_8_T_F(b *testing.B) {
	benchmarkVaryGroupsProcessTime(b, 32, 8, true, false)
}

func BenchmarkVaryGroupsProcessTime32_8_F_T(b *testing.B) {
	benchmarkVaryGroupsProcessTime(b, 32, 8, false, true)
}

func BenchmarkVaryGroupsProcessTime32_8_T_T(b *testing.B) {
	benchmarkVaryGroupsProcessTime(b, 32, 8, true, true)
}

func BenchmarkVaryGroupsProcessTime64_16_F_F(b *testing.B) {
	benchmarkVaryGroupsProcessTime(b, 64, 16, false, false)
}

func BenchmarkVaryGroupsProcessTime64_16_T_F(b *testing.B) {
	benchmarkVaryGroupsProcessTime(b, 64, 16, true, false)
}

func BenchmarkVaryGroupsProcessTime64_16_F_T(b *testing.B) {
	benchmarkVaryGroupsProcessTime(b, 64, 16, false, true)
}

func BenchmarkVaryGroupsProcessTime64_16_T_T(b *testing.B) {
	benchmarkVaryGroupsProcessTime(b, 64, 16, true, true)
}

func BenchmarkVaryGroupsProcessTime128_32_F_F(b *testing.B) {
	benchmarkVaryGroupsProcessTime(b, 128, 32, false, false)
}

func BenchmarkVaryGroupsProcessTime128_32_T_F(b *testing.B) {
	benchmarkVaryGroupsProcessTime(b, 128, 32, true, false)
}

func BenchmarkVaryGroupsProcessTime128_32_F_T(b *testing.B) {
	benchmarkVaryGroupsProcessTime(b, 128, 32, false, true)
}

func BenchmarkVaryGroupsProcessTime128_32_T_T(b *testing.B) {
	benchmarkVaryGroupsProcessTime(b, 128, 32, true, true)
}

/*
func BenchmarkVaryGroupsProcessTime192_48_F_F(b *testing.B) {
	benchmarkVaryGroupsProcessTime(b, 192, 48, false, false)
}

func BenchmarkVaryGroupsProcessTime192_48_T_F(b *testing.B) {
	benchmarkVaryGroupsProcessTime(b, 192, 48, true, false)
}

func BenchmarkVaryGroupsProcessTime192_48_F_T(b *testing.B) {
	benchmarkVaryGroupsProcessTime(b, 192, 48, false, true)
}

func BenchmarkVaryGroupsProcessTime192_48_T_T(b *testing.B) {
	benchmarkVaryGroupsProcessTime(b, 192, 48, true, true)
}

func BenchmarkVaryGroupsProcessTime256_64_F_F(b *testing.B) {
	benchmarkVaryGroupsProcessTime(b, 256, 64, false, false)
}

func BenchmarkVaryGroupsProcessTime256_64_T_F(b *testing.B) {
	benchmarkVaryGroupsProcessTime(b, 256, 64, true, false)
}

func BenchmarkVaryGroupsProcessTime256_64_F_T(b *testing.B) {
	benchmarkVaryGroupsProcessTime(b, 256, 64, false, true)
}

func BenchmarkVaryGroupsProcessTime256_64_T_T(b *testing.B) {
	benchmarkVaryGroupsProcessTime(b, 256, 64, true, true)
}

func BenchmarkVaryGroupsProcessTime320_80_F_F(b *testing.B) {
	benchmarkVaryGroupsProcessTime(b, 320, 80, false, false)
}

func BenchmarkVaryGroupsProcessTime320_80_T_F(b *testing.B) {
	benchmarkVaryGroupsProcessTime(b, 320, 80, true, false)
}

func BenchmarkVaryGroupsProcessTime320_80_F_T(b *testing.B) {
	benchmarkVaryGroupsProcessTime(b, 320, 80, false, true)
}

func BenchmarkVaryGroupsProcessTime320_80_T_T(b *testing.B) {
	benchmarkVaryGroupsProcessTime(b, 320, 80, true, true)
}
*/

func benchmarkVaryGroupsProcessTime(b *testing.B, G, Gstar int, normalUpdates, adminUpdates bool) {
	b.StopTimer()
	adminUpdaters := G/8
	normalUpdaters := G/4
	stateBench, admins := setupGroupWithRandomAdminsBench(G, Gstar)
//	fmt.Println(admins)
	admins = admins[:Gstar]
	states := stateBench.states
	adminupdates := make([]*MLSPlaintext, adminUpdaters)
	normalupdates := make([]*MLSPlaintext, normalUpdaters)

	if !adminUpdates {
		adminUpdaters = 0
	}

	for i := 0; i < adminUpdaters; i++ {
		index := admins[i]
		oldCred := stateBench.keyPackages[i].Credential
		newPriv, _ := oldCred.Scheme().Generate()
		newCred := NewBasicCredential(oldCred.Identity(), oldCred.Scheme(), newPriv.PublicKey)

		newKP, err := NewKeyPackageWithInitKey(suite, stateBench.keyPackages[index].InitKey, newCred, newPriv)
		if err != nil {
			panic(err)
		}

		adminupdates[i], err = states[index].AdminUpdate(&newPriv, *newKP)
	}

	var updaters []int
	if !normalUpdates {
		normalUpdaters = 0
	} else {
		updaters = randomSetWithout(G, admins)[:normalUpdaters]
	}

	for i := 0; i < normalUpdaters; i++ {
		index := updaters[i]
		/*
		oldCred := stateBench.keyPackages[index].Credential
		newPriv, _ := oldCred.Scheme().Generate()
		newCred := NewBasicCredential(oldCred.Identity(), oldCred.Scheme(), newPriv.PublicKey)

		newSecret := randomBytes(32)
		newInitKey, err := suite.hpke().Derive(newSecret)
		if err != nil {
			panic(err)
		}

		newKP, err := NewKeyPackageWithInitKey(suite, newInitKey.PublicKey, newCred, newPriv)

		updateSecret := randomBytes(32)
		normalupdates[i], err = states[index].Update(updateSecret, &newPriv, *newKP)
		*/
		oldCred := stateBench.keyPackages[index].Credential

		newSecret := randomBytes(32)
		newInitKey, err := suite.hpke().Derive(newSecret)

		if err != nil {
			panic(err)
		}

		newKP, err := NewKeyPackageWithInitKey(suite, newInitKey.PublicKey, &oldCred, stateBench.identityPrivs[index])
		if err != nil {
			panic(err)
		}

		normalupdates[i], err = states[index].Update(newSecret, &stateBench.identityPrivs[index], *newKP)
		if err != nil {
			panic(err)
		}


		// can maybe comment out
		/*
		_, err = states[i].Handle(normalupdates[i])
		if err != nil {
			panic(err)
		}
		*/
	}

	ind := rand.Intn(len(admins))
	state := states[admins[ind]]

	for j := 0; j < adminUpdaters; j++ {
		_, err := state.Handle(adminupdates[j])
		if err != nil {
			panic(err)
		}
	}

	for j := 0; j < normalUpdaters; j++ {
		_, err := state.Handle(normalupdates[j])
		if err != nil {
			panic(err)
		}
	}

	secret := randomBytes(32)
	com, _, _, err := state.Commit(secret)
	if err != nil {
		panic(err)
	}

	nonadmins := randomSetWithout(G, admins)

	b.StartTimer()
	for i := 0; i < b.N; i++ {
		ind := rand.Intn(len(nonadmins))
		state = states[nonadmins[ind]]

		for j := 0; j < adminUpdaters; j++ {
			_, err := state.Handle(adminupdates[j])
			if err != nil {
				panic(err)
			}
		}

		for j := 0; j < normalUpdaters; j++ {
			_, err := state.Handle(normalupdates[j])
			if err != nil {
				panic(err)
			}
		}

		 _, _ = state.Handle(com)
	}

}

func benchmarkFixedGroupsCommitTime(b *testing.B, upd, adminupd int) {
	b.StopTimer()
	G := 64
	Gstar := 16
	adminUpdaters := adminupd
	normalUpdaters := upd
	stateBench, admins := setupGroupWithRandomAdminsBench(G, Gstar)
//	fmt.Println(admins)
	admins = admins[:Gstar]
	states := stateBench.states
	adminupdates := make([]*MLSPlaintext, adminUpdaters)
	normalupdates := make([]*MLSPlaintext, normalUpdaters)

	for i := 0; i < adminUpdaters; i++ {
		index := admins[i]
		oldCred := stateBench.keyPackages[i].Credential
		newPriv, _ := oldCred.Scheme().Generate()
		newCred := NewBasicCredential(oldCred.Identity(), oldCred.Scheme(), newPriv.PublicKey)

		newKP, err := NewKeyPackageWithInitKey(suite, stateBench.keyPackages[index].InitKey, newCred, newPriv)
		if err != nil {
			panic(err)
		}

		adminupdates[i], err = states[index].AdminUpdate(&newPriv, *newKP)
	}

	var updaters []int
	if upd > 0 {
		updaters = randomSetWithout(G, admins)[:normalUpdaters]
	}

	for i := 0; i < normalUpdaters; i++ {
		index := updaters[i]
		/*
		oldCred := stateBench.keyPackages[index].Credential
		newPriv, _ := oldCred.Scheme().Generate()
		newCred := NewBasicCredential(oldCred.Identity(), oldCred.Scheme(), newPriv.PublicKey)

		newSecret := randomBytes(32)
		newInitKey, err := suite.hpke().Derive(newSecret)
		if err != nil {
			panic(err)
		}

		newKP, err := NewKeyPackageWithInitKey(suite, newInitKey.PublicKey, newCred, newPriv)

		updateSecret := randomBytes(32)
		normalupdates[i], err = states[index].Update(updateSecret, &newPriv, *newKP)
		*/
		oldCred := stateBench.keyPackages[index].Credential

		newSecret := randomBytes(32)
		newInitKey, err := suite.hpke().Derive(newSecret)

		if err != nil {
			panic(err)
		}

		newKP, err := NewKeyPackageWithInitKey(suite, newInitKey.PublicKey, &oldCred, stateBench.identityPrivs[index])
		if err != nil {
			panic(err)
		}

		normalupdates[i], err = states[index].Update(newSecret, &stateBench.identityPrivs[index], *newKP)
		if err != nil {
			panic(err)
		}


		// can maybe comment out
		/*
		_, err = states[i].Handle(normalupdates[i])
		if err != nil {
			panic(err)
		}
		*/
	}

	state := states[0]
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		ind := rand.Intn(len(admins))
		state = states[admins[ind]]

		for j := 0; j < adminUpdaters; j++ {
			_, err := state.Handle(adminupdates[j])
			if err != nil {
				panic(err)
			}
		}

		for j := 0; j < normalUpdaters; j++ {
			_, err := state.Handle(normalupdates[j])
			if err != nil {
				panic(err)
			}
		}

		secret := randomBytes(32)
		_, _, _, _ = state.Commit(secret)
	}

}

func BenchmarkFixedGroupsCommitTimeF_F(b *testing.B) {
	benchmarkFixedGroupsCommitTime(b, 0, 0)
}

func BenchmarkFixedGroupsCommitTimeT_F_4_2(b *testing.B) {
	benchmarkFixedGroupsCommitTime(b, 4, 0)
}

func BenchmarkFixedGroupsCommitTimeF_T_4_2(b *testing.B) {
	benchmarkFixedGroupsCommitTime(b, 0, 2)
}

func BenchmarkFixedGroupsCommitTimeT_T_4_2(b *testing.B) {
	benchmarkFixedGroupsCommitTime(b, 4, 2)
}

func BenchmarkFixedGroupsCommitTimeT_F_8_4(b *testing.B) {
	benchmarkFixedGroupsCommitTime(b, 8, 0)
}

func BenchmarkFixedGroupsCommitTimeF_T_8_4(b *testing.B) {
	benchmarkFixedGroupsCommitTime(b, 0, 4)
}

func BenchmarkFixedGroupsCommitTimeT_T_8_4(b *testing.B) {
	benchmarkFixedGroupsCommitTime(b, 8, 4)
}

func BenchmarkFixedGroupsCommitTimeT_F_12_6(b *testing.B) {
	benchmarkFixedGroupsCommitTime(b, 12, 0)
}

func BenchmarkFixedGroupsCommitTimeF_T_12_6(b *testing.B) {
	benchmarkFixedGroupsCommitTime(b, 0, 6)
}

func BenchmarkFixedGroupsCommitTimeT_T_12_6(b *testing.B) {
	benchmarkFixedGroupsCommitTime(b, 12, 6)
}

func BenchmarkFixedGroupsCommitTimeT_F_16_8(b *testing.B) {
	benchmarkFixedGroupsCommitTime(b, 16, 0)
}

func BenchmarkFixedGroupsCommitTimeF_T_16_8(b *testing.B) {
	benchmarkFixedGroupsCommitTime(b, 0, 8)
}

func BenchmarkFixedGroupsCommitTimeT_T_16_8(b *testing.B) {
	benchmarkFixedGroupsCommitTime(b, 16, 8)
}

func BenchmarkFixedGroupsCommitTimeT_F_20_10(b *testing.B) {
	benchmarkFixedGroupsCommitTime(b, 20, 0)
}

func BenchmarkFixedGroupsCommitTimeF_T_20_10(b *testing.B) {
	benchmarkFixedGroupsCommitTime(b, 0, 10)
}

func BenchmarkFixedGroupsCommitTimeT_T_20_10(b *testing.B) {
	benchmarkFixedGroupsCommitTime(b, 20, 10)
}

func BenchmarkFixedGroupsCommitTimeT_F_24_12(b *testing.B) {
	benchmarkFixedGroupsCommitTime(b, 24, 0)
}

func BenchmarkFixedGroupsCommitTimeF_T_24_12(b *testing.B) {
	benchmarkFixedGroupsCommitTime(b, 0, 12)
}

func BenchmarkFixedGroupsCommitTimeT_T_24_12(b *testing.B) {
	benchmarkFixedGroupsCommitTime(b, 24, 12)
}

func BenchmarkFixedGroupsCommitTimeT_F_28_14(b *testing.B) {
	benchmarkFixedGroupsCommitTime(b, 28, 0)
}

func BenchmarkFixedGroupsCommitTimeF_T_28_14(b *testing.B) {
	benchmarkFixedGroupsCommitTime(b, 0, 14)
}

func BenchmarkFixedGroupsCommitTimeT_T_28_14(b *testing.B) {
	benchmarkFixedGroupsCommitTime(b, 28, 14)
}

func BenchmarkFixedGroupsCommitTimeT_F_32_16(b *testing.B) {
	benchmarkFixedGroupsCommitTime(b, 32, 0)
}

func BenchmarkFixedGroupsCommitTimeF_T_32_16(b *testing.B) {
	benchmarkFixedGroupsCommitTime(b, 0, 16)
}

func BenchmarkFixedGroupsCommitTimeT_T_32_16(b *testing.B) {
	benchmarkFixedGroupsCommitTime(b, 32, 16)
}

func benchmarkFixedGroupsProcessTime(b *testing.B, upd, adminupd int) {
	b.StopTimer()
	G := 64
	Gstar := 16
	adminUpdaters := adminupd
	normalUpdaters := upd
	stateBench, admins := setupGroupWithRandomAdminsBench(G, Gstar)
//	fmt.Println(admins)
	admins = admins[:Gstar]
	states := stateBench.states
	adminupdates := make([]*MLSPlaintext, adminUpdaters)
	normalupdates := make([]*MLSPlaintext, normalUpdaters)

	for i := 0; i < adminUpdaters; i++ {
		index := admins[i]
		oldCred := stateBench.keyPackages[i].Credential
		newPriv, _ := oldCred.Scheme().Generate()
		newCred := NewBasicCredential(oldCred.Identity(), oldCred.Scheme(), newPriv.PublicKey)

		newKP, err := NewKeyPackageWithInitKey(suite, stateBench.keyPackages[index].InitKey, newCred, newPriv)
		if err != nil {
			panic(err)
		}

		adminupdates[i], err = states[index].AdminUpdate(&newPriv, *newKP)
	}

	var updaters []int
	if upd > 0 {
		updaters = randomSetWithout(G, admins)[:normalUpdaters]
	}

	for i := 0; i < normalUpdaters; i++ {
		index := updaters[i]
		/*
		oldCred := stateBench.keyPackages[index].Credential
		newPriv, _ := oldCred.Scheme().Generate()
		newCred := NewBasicCredential(oldCred.Identity(), oldCred.Scheme(), newPriv.PublicKey)

		newSecret := randomBytes(32)
		newInitKey, err := suite.hpke().Derive(newSecret)
		if err != nil {
			panic(err)
		}

		newKP, err := NewKeyPackageWithInitKey(suite, newInitKey.PublicKey, newCred, newPriv)

		updateSecret := randomBytes(32)
		normalupdates[i], err = states[index].Update(updateSecret, &newPriv, *newKP)

		*/
		oldCred := stateBench.keyPackages[index].Credential

		newSecret := randomBytes(32)
		newInitKey, err := suite.hpke().Derive(newSecret)

		if err != nil {
			panic(err)
		}

		newKP, err := NewKeyPackageWithInitKey(suite, newInitKey.PublicKey, &oldCred, stateBench.identityPrivs[index])
		if err != nil {
			panic(err)
		}

		normalupdates[i], err = states[index].Update(newSecret, &stateBench.identityPrivs[index], *newKP)
		if err != nil {
			panic(err)
		}
		// can maybe comment out
		/*
		_, err = states[i].Handle(normalupdates[i])
		if err != nil {
			panic(err)
		}
		*/
	}

	ind := rand.Intn(len(admins))
	state := states[admins[ind]]

	for j := 0; j < adminUpdaters; j++ {
		_, err := state.Handle(adminupdates[j])
		if err != nil {
			panic(err)
		}
	}

	for j := 0; j < normalUpdaters; j++ {
		_, err := state.Handle(normalupdates[j])
		if err != nil {
			panic(err)
		}
	}

	secret := randomBytes(32)
	com, _, _, err := state.Commit(secret)
	if err != nil {
		panic(err)
	}

	nonadmins := randomSetWithout(G, admins)

	b.StartTimer()
	for i := 0; i < b.N; i++ {
		ind := rand.Intn(len(nonadmins))
		state = states[nonadmins[ind]]

		for j := 0; j < adminUpdaters; j++ {
			_, err := state.Handle(adminupdates[j])
			if err != nil {
				panic(err)
			}
		}

		for j := 0; j < normalUpdaters; j++ {
			_, err := state.Handle(normalupdates[j])
			if err != nil {
				panic(err)
			}
		}

		 _, _ = state.Handle(com)
	}

}

func BenchmarkFixedGroupsProcessTimeF_F(b *testing.B) {
	benchmarkFixedGroupsProcessTime(b, 0, 0)
}

func BenchmarkFixedGroupsProcessTimeT_F_4_2(b *testing.B) {
	benchmarkFixedGroupsProcessTime(b, 4, 0)
}

func BenchmarkFixedGroupsProcessTimeF_T_4_2(b *testing.B) {
	benchmarkFixedGroupsProcessTime(b, 0, 2)
}

func BenchmarkFixedGroupsProcessTimeT_T_4_2(b *testing.B) {
	benchmarkFixedGroupsProcessTime(b, 4, 2)
}

func BenchmarkFixedGroupsProcessTimeT_F_8_4(b *testing.B) {
	benchmarkFixedGroupsProcessTime(b, 8, 0)
}

func BenchmarkFixedGroupsProcessTimeF_T_8_4(b *testing.B) {
	benchmarkFixedGroupsProcessTime(b, 0, 4)
}

func BenchmarkFixedGroupsProcessTimeT_T_8_4(b *testing.B) {
	benchmarkFixedGroupsProcessTime(b, 8, 4)
}

func BenchmarkFixedGroupsProcessTimeT_F_12_6(b *testing.B) {
	benchmarkFixedGroupsProcessTime(b, 12, 0)
}

func BenchmarkFixedGroupsProcessTimeF_T_12_6(b *testing.B) {
	benchmarkFixedGroupsProcessTime(b, 0, 6)
}

func BenchmarkFixedGroupsProcessTimeT_T_12_6(b *testing.B) {
	benchmarkFixedGroupsProcessTime(b, 12, 6)
}

func BenchmarkFixedGroupsProcessTimeT_F_16_8(b *testing.B) {
	benchmarkFixedGroupsProcessTime(b, 16, 0)
}

func BenchmarkFixedGroupsProcessTimeF_T_16_8(b *testing.B) {
	benchmarkFixedGroupsProcessTime(b, 0, 8)
}

func BenchmarkFixedGroupsProcessTimeT_T_16_8(b *testing.B) {
	benchmarkFixedGroupsProcessTime(b, 16, 8)
}

func BenchmarkFixedGroupsProcessTimeT_F_20_10(b *testing.B) {
	benchmarkFixedGroupsProcessTime(b, 20, 0)
}

func BenchmarkFixedGroupsProcessTimeF_T_20_10(b *testing.B) {
	benchmarkFixedGroupsProcessTime(b, 0, 10)
}

func BenchmarkFixedGroupsProcessTimeT_T_20_10(b *testing.B) {
	benchmarkFixedGroupsProcessTime(b, 20, 10)
}

func BenchmarkFixedGroupsProcessTimeT_F_24_12(b *testing.B) {
	benchmarkFixedGroupsProcessTime(b, 24, 0)
}

func BenchmarkFixedGroupsProcessTimeF_T_24_12(b *testing.B) {
	benchmarkFixedGroupsProcessTime(b, 0, 12)
}

func BenchmarkFixedGroupsProcessTimeT_T_24_12(b *testing.B) {
	benchmarkFixedGroupsProcessTime(b, 24, 12)
}

func BenchmarkFixedGroupsProcessTimeT_F_28_14(b *testing.B) {
	benchmarkFixedGroupsProcessTime(b, 28, 0)
}

func BenchmarkFixedGroupsProcessTimeF_T_28_14(b *testing.B) {
	benchmarkFixedGroupsProcessTime(b, 0, 14)
}

func BenchmarkFixedGroupsProcessTimeT_T_28_14(b *testing.B) {
	benchmarkFixedGroupsProcessTime(b, 28, 14)
}

func BenchmarkFixedGroupsProcessTimeT_F_32_16(b *testing.B) {
	benchmarkFixedGroupsProcessTime(b, 32, 0)
}

func BenchmarkFixedGroupsProcessTimeF_T_32_16(b *testing.B) {
	benchmarkFixedGroupsProcessTime(b, 0, 16)
}

func BenchmarkFixedGroupsProcessTimeT_T_32_16(b *testing.B) {
	benchmarkFixedGroupsProcessTime(b, 32, 16)
}
