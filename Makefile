CRYPTOLPATH=${PWD}/deps/cryptol-specs
COV_REP=${PWD}/../crucible/crux-mir/report-coverage/Cargo.toml

COVERAGE=--branch-coverage --path-sat --output-directory test-coverage

clean:
	cargo clean
	rm -rf test-coverage

verify-cryptolspecs:
	CRYPTOLPATH=${CRYPTOLPATH} CRUX_MIR=crux-mir-comp cargo crux-test --lib -- ${COVERAGE} -s z3 -m message_schedule_one_equiv
	CRYPTOLPATH=${CRYPTOLPATH} CRUX_MIR=crux-mir-comp cargo crux-test --lib -- ${COVERAGE} -s z3 -m compress_t1_equiv

verify-hacspecs:
	CRUX_MIR=crux-mir-comp cargo crux-test --lib -- ${COVERAGE} -s z3 -m ch_equiv
	CRUX_MIR=crux-mir-comp cargo crux-test --lib -- ${COVERAGE} -s z3 -m maj_equiv
	CRUX_MIR=crux-mir-comp cargo crux-test --lib -- ${COVERAGE} -s z3 -m SIGMA_0_equiv
	CRUX_MIR=crux-mir-comp cargo crux-test --lib -- ${COVERAGE} -s z3 -m SIGMA_1_equiv
	CRUX_MIR=crux-mir-comp cargo crux-test --lib -- ${COVERAGE} -s z3 -m sigma_0_equiv
	CRUX_MIR=crux-mir-comp cargo crux-test --lib -- ${COVERAGE} -s z3 -m sigma_1_equiv
	CRUX_MIR=crux-mir-comp cargo crux-test --lib -- ${COVERAGE} -s z3 -m compress_t1_equiv
	CRUX_MIR=crux-mir-comp cargo crux-test --lib -- ${COVERAGE} -s z3 -m compress_t2_equiv
#	compress_words_equiv

coverage:
	find ./test-coverage -name 'report_data.js' | xargs cargo run --manifest-path ${COV_REP} --

patch:
	cd deps/hacspec && `git apply ../hacspec.patch

