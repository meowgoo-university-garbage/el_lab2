package main

import "core:fmt"
import "core:slice"
import "core:math/rand"

import "./rsa"
import "core:crypto/hash"
import "core:math/big"

BALLOT_SET_COUNT :: 10
CANDIDATE_COUNT :: 2

Country :: enum {
    Ukraine,
    Russia,
    Poland,
}

Person :: struct {
    id : u64,
    fullname : string,
    country : Country,
    age : int,

    key_prv : rsa.Key_Private,
    key_pub : rsa.Key_Public,
}

Voter :: struct {
    id : u64,
    fullname : string,
    key_pub : rsa.Key_Public,
    alreadyVoted : bool,
}

Candidate :: struct {
    id : u64,
    fullname : string,
    votes : int,
}

ElectionCommission :: struct {
    candidates : []Candidate,

    key_prv : rsa.Key_Private,
    key_pub : rsa.Key_Public,

    send_key_prv : rsa.Key_Private,
    send_key_pub : rsa.Key_Public,
}

Ballot :: struct {
    ballot_id       : u64,
    candidate_id    : u64,
}

BallotHash :: struct {
    ballot : Ballot,
    hash : []u8,
    maskedHash : []u8,
    blind, unblind : big.Int,
}

BallotHashVerification :: struct {
    ballot : Ballot,
    blind : big.Int,
}

SignedBallot :: struct {
    ballot : []u8,
    ecSignature : []u8,
}

eqbreak :: proc () {
    fmt.println("==============================================================")
}

main :: proc () {
    people : []Person = {
        Person{ id = 0, fullname = "Vitalya Gryb", country = .Ukraine, age = 23 },
        Person{ id = 1, fullname = "Svitlana Zhizha", country = .Ukraine, age = 27 },
        // Person{ id = 2, fullname = "Zheka Zrada", country = .Russia, age = 19 },
        // Person{ id = 3, fullname = "Grzegorz Brzeczyszczykiewicz", country = .Poland, age = 153 },
        // Person{ id = 4, fullname = "little boy", country = .Ukraine, age = 4 },
        // Person{ id = 5, fullname = "Yaroslav Aboba", country = .Ukraine, age = 34 },
        // Person{ id = 6, fullname = "Vova Ugabuga", country = .Ukraine, age = 7182 },
        // Person{ id = 7, fullname = "Mariya Kavun", country = .Ukraine, age = 26 },
    }



    for &p in people {
        p.key_prv, p.key_pub = rsa.keygen()
        fmt.printfln("Generated private key for %v", p.fullname)
    }
    fmt.println()



    fmt.println("Forming a list of eligible voters")
    voters : [dynamic]Voter
    for &p in people {
        fmt.printfln("Examining %v", p.fullname)

        if p.country != .Ukraine {
            fmt.printfln("\tINELIGIBLE: You have to be a citizen of Ukraine to vote")
            continue
        }
        if p.age < 18 {
            fmt.printfln("\tINELIGIBLE: You have to be an adult to vote")
            continue
        }

        fmt.printfln("\tVOTER REGISTERED")
        append(&voters, Voter{ p.id, p.fullname, p.key_pub, false })
    }
    fmt.println()

    fmt.println("List of eligible voters")
    for v in voters {
        fmt.printfln("%v", v.fullname)
    }
    fmt.println()



    ec : ElectionCommission = {
        candidates = {
            Candidate{ 67, "Petro Poroshenko", 0 },
            Candidate{ 69, "Amogus", 0 },
        }
    }

    ec.key_prv, ec.key_pub = rsa.keygen()
    ec.send_key_prv, ec.send_key_pub = rsa.keygen()
    fmt.printfln("Generated private keys for signing and sending for ELECTION COMMISSION")
    
    EC_PUBLIC_KEY := ec.key_pub
    EC_SEND_PUBLIC_KEY := ec.send_key_pub
    fmt.println()



    fmt.println("List of candidates")
    for c in ec.candidates {
        fmt.printfln("%v", c.fullname)
    }
    fmt.println()



    fmt.printfln("VOTING STARTED")
    submittedBallots : [dynamic]SignedBallot
    nextPerson: for &p in people {
        eqbreak()

        {
            context.user_ptr = &p.id
            pi, _ := slice.linear_search_proc(people, proc (p : Person) -> bool { return (p.id == (cast(^u64)context.user_ptr)^) })

            fmt.printfln("VOTER> Ballot request by %v", people[pi].fullname)
        }

        ballotSets : [BALLOT_SET_COUNT][CANDIDATE_COUNT]Ballot

        for &s in ballotSets {
            id := rand.uint64()

            for &b, i in s {
                b = Ballot{
                    ballot_id = id,
                    candidate_id = ec.candidates[i].id,
                }
            }
        }

        fmt.printfln("VOTER> Formed %v sets", BALLOT_SET_COUNT)

        hashes : [BALLOT_SET_COUNT][CANDIDATE_COUNT]BallotHash
        maskedHashes : [BALLOT_SET_COUNT][CANDIDATE_COUNT][]u8
        messageBlob : [dynamic]u8
        defer delete(messageBlob)

        defer for &s in hashes {
            for &h in s {
                delete(h.hash)
                delete(h.maskedHash)
                big.destroy(&h.blind, &h.unblind)
            }
        }

        for &s, si in hashes {
            for &bhash, bi in s {
                ballot := ballotSets[si][bi]

                hash := hash.hash_bytes(.SHA256, slice.bytes_from_ptr(&ballot, size_of(Ballot)))
                r, r1 := rsa.blindGenerate(&EC_PUBLIC_KEY)
                maskedHash := rsa.blindMask(&EC_PUBLIC_KEY, &r, hash)

                bhash = BallotHash{
                    ballot = ballot,
                    hash = hash,
                    maskedHash = maskedHash,
                    blind = r,
                    unblind = r1,
                }
                maskedHashes[si][bi] = maskedHash
                append(&messageBlob, ..maskedHash)
            }
        }

        fmt.printfln("VOTER> Generated masked hashes for all ballot sets")

        signature := rsa.sign(&p.key_prv, messageBlob[:])
        claimedVoterId := p.id


        fmt.printfln("VOTER -> EC> Sending (masked hashes, voter signature, voter id) to election commission")


        // ELECTION COMMISION
        receivedMaskedHashes := maskedHashes
        receivedSignature := signature
        receivedVoterId := claimedVoterId

        fmt.printfln("EC> Received voter's request")

        context.user_ptr = &receivedVoterId
        pi, _ := slice.linear_search_proc(people, proc (p : Person) -> bool { return (p.id == (cast(^u64)context.user_ptr)^) })

        fmt.printfln("EC> Request from claimed voter: %v", people[pi].fullname)

        context.user_ptr = &receivedVoterId
        vi, vf := slice.linear_search_proc(voters[:], proc (v : Voter) -> bool { return (v.id == (cast(^u64)context.user_ptr)^) })

        if !vf {
            fmt.printfln("EC> DISMISSED: %v is not eligible for voting", people[pi].fullname)
            continue nextPerson
        }

        if voters[vi].alreadyVoted {
            fmt.printfln("EC> DISMISSED: %v has already received their signed ballot set", people[pi].fullname)
            continue nextPerson
        }





        restoredMessageBlob : [dynamic]u8
        defer delete(restoredMessageBlob)

        for &s in receivedMaskedHashes {
            for &mh in s {
                append(&restoredMessageBlob, ..mh)
            }
        }

        if !rsa.verify(&voters[vi].key_pub, restoredMessageBlob[:], receivedSignature) {
            fmt.printfln("EC> DISMISSED: couldn't verify request's authenticity")
            continue nextPerson
        }
        else {
            fmt.printfln("EC> verified request's authenticity")
        }

        ecChosenBallotSetIndex := rand.int_range(0, BALLOT_SET_COUNT)

        fmt.printfln("EC> Voter's request is valid, all ballot sets except %v must now be verified", ecChosenBallotSetIndex)

        fmt.printfln("EC -> VOTER> Sending (chosen ballot set index) to the voter")




        // BACK TO VOTER
        chosenBallotSetIndex := ecChosenBallotSetIndex

        fmt.printfln("VOTER> Received ballot set index %v", chosenBallotSetIndex)

        verification : [BALLOT_SET_COUNT][CANDIDATE_COUNT]BallotHashVerification
        for &s, si in hashes {
            if si == chosenBallotSetIndex { continue }

            for &b, bi in s {
                verification[si][bi] = {
                    ballot = b.ballot,
                    blind = b.blind,
                }
            }
        }

        fmt.printfln("VOTER> Packed all requested verification info")

        fmt.printfln("VOTER -> EC> Sending (original ballots, original blind multipliers) to election commission")

        // BACK TO ELECTION COMMISSION

        receivedVerification := verification
        fmt.printfln("EC> Received voter's verification data")

        for &s, si in receivedVerification {
            if si == ecChosenBallotSetIndex { continue }

            set_id : u64

            for &v, bi in s {
                if bi == 0 {
                    set_id = v.ballot.ballot_id
                }

                if v.ballot.ballot_id != set_id {
                    fmt.printfln("EC> DISMISSED: Ballot set must have the same ballot_id across all of its ballots")
                    continue nextPerson
                }

                if v.ballot.candidate_id != ec.candidates[bi].id {
                    fmt.printfln("EC> DISMISSED: Ballot set must contain a ballot for each candidate, in order")
                    continue nextPerson
                }

                hash := hash.hash_bytes(.SHA256, slice.bytes_from_ptr(&v.ballot, size_of(Ballot)))
                restoredMaskedHash := rsa.blindMask(&EC_PUBLIC_KEY, &v.blind, hash)
                originalMaskedHash := receivedMaskedHashes[si][bi]

                if !slice.equal(restoredMaskedHash, originalMaskedHash) {
                    fmt.printfln("EC> DISMISSED: Verification does not match originally sent hash")
                    continue nextPerson
                }
            }
        }

        fmt.printfln("EC> Received ballot sets match previously sent hashes, guess it's all fine")

        signaturesForMaskedHashes : [CANDIDATE_COUNT][]u8
        defer for &s in signaturesForMaskedHashes { delete(s) }

        for &s, bi in signaturesForMaskedHashes {
            s = rsa.sign_raw(&ec.key_prv, receivedMaskedHashes[ecChosenBallotSetIndex][bi])
        }

        voters[vi].alreadyVoted = true

        fmt.printfln("EC> Generated signatures for all ballots of the chosen set, tracked the voter")

        fmt.printfln("EC -> VOTER> Sending signatures to the voter")


        // BACK TO THE VOTER FOR THE FINAL TIME
        receivedSignaturesForMaskedHashes := signaturesForMaskedHashes
        fmt.printfln("VOTER> Received masked signatures from the election commission")

        signaturesForHashes : [CANDIDATE_COUNT][]u8
        defer for &s in signaturesForHashes { delete(s) }

        for &s, i in receivedSignaturesForMaskedHashes {
            signaturesForHashes[i] = rsa.blindUnmask(&EC_PUBLIC_KEY, &hashes[chosenBallotSetIndex][i].unblind, s)
        }

        fmt.printfln("VOTER> Unmasked all received signatures")

        signedBallots : [CANDIDATE_COUNT]SignedBallot
        defer for &sb in signedBallots { delete(sb.ballot) }
        for &sb, i in signedBallots {
            e, _ := rsa.encrypt_value(&EC_SEND_PUBLIC_KEY, ballotSets[chosenBallotSetIndex][i])

            sb = SignedBallot{
                ballot = e,
                ecSignature = signaturesForHashes[i],
            }
        }

        chosenBallotIndex := rand.int_range(0, len(signedBallots))

        chosenBallot := signedBallots[chosenBallotIndex]
        chosenBallot.ballot = slice.clone(chosenBallot.ballot)
        chosenBallot.ecSignature = slice.clone(chosenBallot.ecSignature)

        context.user_ptr = &ballotSets[chosenBallotSetIndex][chosenBallotIndex].candidate_id
        ci, cf := slice.linear_search_proc(ec.candidates, proc (c : Candidate) -> bool { return (c.id == (cast(^u64)context.user_ptr)^) })

        append(&submittedBallots, chosenBallot)

        fmt.printfln("VOTER> Sent a signed ballot voting for %v. Ballot ID: %v", ec.candidates[ci].fullname, ballotSets[chosenBallotSetIndex][chosenBallotIndex].ballot_id)
    }
    eqbreak()
    fmt.println()



    fmt.println("COUNTING VOTES")
    rand.shuffle(submittedBallots[:])
    trackedIds : map[u64](struct{})
    validBallots : [dynamic]Ballot
    for &sb, i in submittedBallots {
        fmt.printfln("Processing ballot #%v", i)

        ballot, result := rsa.decrypt_value(&ec.send_key_prv, sb.ballot, Ballot)
        if !result {
            fmt.printfln("\tDISMISSED: Failed to decrypt the ballot using SEND private key")
            continue
        }
        fmt.printfln("\tINFO: Decrypted the ballot")

        if !rsa.verify_value(&EC_PUBLIC_KEY, ballot, sb.ecSignature) {
            fmt.printfln("\tDISMISSED: Couldn't verify ballot's authenticity from Election Commission")
            continue
        }
        fmt.printfln("\tINFO: Verified Election Commission's signature")

        _, ok := trackedIds[ballot.ballot_id]
        if ok {
            fmt.printfln("\tDISMISSED: Ballot with the same id received twice")
            continue
        }

        context.user_ptr = &ballot.candidate_id
        ci, cf := slice.linear_search_proc(ec.candidates, proc (c : Candidate) -> bool { return (c.id == (cast(^u64)context.user_ptr)^) })

        if !cf {
            fmt.printfln("\tDISMISSED: candidate with id %v doesn't exist", ballot.candidate_id)
            continue
        }

        fmt.printfln("\tINFO: Chosen candidate: %v", ec.candidates[ci].fullname)

        trackedIds[ballot.ballot_id] = {}
        append(&validBallots, ballot)
        ec.candidates[ci].votes += 1

        fmt.printfln("\tVote counted")
    }
    fmt.println()



    fmt.printfln("ELECTION RESULTS:")
    for c in ec.candidates {
        fmt.printfln("%v:\n\t%v votes", c.fullname, c.votes)
    }
    fmt.println()

    fmt.printfln("BALLOTS:")
    for &vb in validBallots {
        context.user_ptr = &vb.candidate_id
        ci, _ := slice.linear_search_proc(ec.candidates, proc (c : Candidate) -> bool { return (c.id == (cast(^u64)context.user_ptr)^) })

        fmt.printfln("\tID: %v | Candidate: %v", vb.ballot_id, ec.candidates[ci].fullname)
    }


    fmt.println("Hello, World!")
}
