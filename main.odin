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
    ballot : Ballot,
    ecSignature : []u8,
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
    fmt.printfln("Generated private key for ELECTION COMMISSION")
    
    EC_PUBLIC_KEY := ec.key_pub
    fmt.println()



    fmt.println("List of candidates")
    for c in ec.candidates {
        fmt.printfln("%v", c.fullname)
    }
    fmt.println()



    fmt.printfln("VOTING STARTED")
    submittedBallots : [dynamic]SignedBallot
    nextPerson: for &p in people {
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

        hashes : [BALLOT_SET_COUNT][CANDIDATE_COUNT]BallotHash
        mashedHashes : [BALLOT_SET_COUNT][CANDIDATE_COUNT][]u8
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
                mashedHashes[si][bi] = maskedHash
                append(&messageBlob, ..maskedHash)
            }
        }

        signature := rsa.sign(&p.key_prv, messageBlob[:])
        claimedVoterId := p.id




        // ELECTION COMMISION
        receivedMaskedHashes := mashedHashes
        receivedSignature := signature
        receivedVoterId := claimedVoterId

        context.user_ptr = &receivedVoterId
        pi, _ := slice.linear_search_proc(people, proc (p : Person) -> bool { return (p.id == (cast(^u64)context.user_ptr)^) })

        fmt.printfln("\tINFO: Request from claimed voter: %v", people[pi].fullname)

        context.user_ptr = &receivedVoterId
        vi, vf := slice.linear_search_proc(voters[:], proc (v : Voter) -> bool { return (v.id == (cast(^u64)context.user_ptr)^) })

        if !vf {
            fmt.printfln("\tDISMISSED: %v is not eligible for voting", people[pi].fullname)
            continue nextPerson
        }

        if voters[vi].alreadyVoted {
            fmt.printfln("\tDISMISSED: %v has already received their signed ballot set", people[pi].fullname)
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
            fmt.printfln("\tDISMISSED: couldn't verify request's authenticity")
            continue nextPerson
        }
        else {
            fmt.printfln("\tINFO: verified request's authenticity")
        }

        ecChosenBallotSetIndex := rand.int_range(0, BALLOT_SET_COUNT)




        // BACK TO VOTER
        chosenBallotSetIndex := ecChosenBallotSetIndex

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



        // BACK TO ELECTION COMMISSION

        receivedVerification := verification

        for &s, si in receivedVerification {
            if si == ecChosenBallotSetIndex { continue }

            set_id : u64

            for &v, bi in s {
                if bi == 0 {
                    set_id = v.ballot.ballot_id
                }

                if v.ballot.ballot_id != set_id {
                    fmt.printfln("\tDISMISSED: Ballot set must have the same ballot_id across all of its ballots")
                    continue nextPerson
                }

                if v.ballot.candidate_id != ec.candidates[bi].id {
                    fmt.printfln("\tDISMISSED: Ballot set must contain a ballot for each candidate, in order")
                    continue nextPerson
                }

                hash := hash.hash_bytes(.SHA256, slice.bytes_from_ptr(&v.ballot, size_of(Ballot)))
                restoredMaskedHash := rsa.blindMask(&EC_PUBLIC_KEY, &v.blind, hash)
                originalMaskedHash := receivedMaskedHashes[si][bi]

                if !slice.equal(restoredMaskedHash, originalMaskedHash) {
                    fmt.printfln("\tDISMISSED: Verification does not match originally sent hash")
                    continue nextPerson
                }
            }
        }

        fmt.printfln("\tINFO: Received ballot sets match previously sent hashes, guess it's all fine")

        signaturesForMaskedHashes : [CANDIDATE_COUNT][]u8
        defer for &s in signaturesForMaskedHashes { delete(s) }

        for &s, bi in signaturesForMaskedHashes {
            s = rsa.sign_raw(&ec.key_prv, receivedMaskedHashes[ecChosenBallotSetIndex][bi])
        }

        voters[vi].alreadyVoted = true



        // BACK TO THE VOTER FOR THE FINAL TIME
        receivedSignaturesForMaskedHashes := signaturesForMaskedHashes

        signaturesForHashes : [CANDIDATE_COUNT][]u8
        defer for &s in signaturesForHashes { delete(s) }

        for &s, i in receivedSignaturesForMaskedHashes {
            signaturesForHashes[i] = rsa.blindUnmask(&EC_PUBLIC_KEY, &hashes[chosenBallotSetIndex][i].unblind, s)
        }

        signedBallots : [CANDIDATE_COUNT]SignedBallot
        for &sb, i in signedBallots {
            sb = SignedBallot{
                ballot = ballotSets[chosenBallotSetIndex][i],
                ecSignature = signaturesForHashes[i],
            }
        }

        chosenBallot := rand.choice(signedBallots[:])
        chosenBallot.ecSignature = slice.clone(chosenBallot.ecSignature)
        append(&submittedBallots, chosenBallot)
    }
    fmt.println()



    fmt.println("COUNTING VOTES")
    rand.shuffle(submittedBallots[:])
    trackedIds : map[u64](struct{})
    validBallots : [dynamic]Ballot
    for &sb, i in submittedBallots {
        if !rsa.verify_value(&EC_PUBLIC_KEY, sb.ballot, sb.ecSignature) {
            fmt.printfln("\tDISMISSED: Couldn't verify ballot's authenticity from Election Commission")
            continue
        }

        _, ok := trackedIds[sb.ballot.ballot_id]
        if ok {
            fmt.printfln("\tDISMISSED: Ballot with the same id received twice")
            continue
        }

        context.user_ptr = &sb.ballot.candidate_id
        ci, cf := slice.linear_search_proc(ec.candidates, proc (c : Candidate) -> bool { return (c.id == (cast(^u64)context.user_ptr)^) })

        if !cf {
            fmt.printfln("\tDISMISSED: candidate with id %v doesn't exist", sb.ballot.candidate_id)
            continue
        }

        fmt.printfln("\tINFO: Chosen candidate: %v", ec.candidates[ci].fullname)

        trackedIds[sb.ballot.ballot_id] = {}
        append(&validBallots, sb.ballot)
        ec.candidates[ci].votes += 1
    }
    fmt.println()



    fmt.printfln("ELECTION RESULTS:")
    for c in ec.candidates {
        fmt.printfln("%v:\n\t%v votes", c.fullname, c.votes)
    }


    fmt.println("Hello, World!")
}
