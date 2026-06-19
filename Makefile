CRYPTOLPATH=${PWD}/deps/cryptol-specs
COV_REP=${PWD}/../crucible/crux-mir/report-coverage/Cargo.toml

# Adding `--branch-coverage` triggers an error, see
# https://github.com/GaloisInc/crucible/issues/1534#issuecomment-4718780378
# for details
COVERAGE=--path-sat --output-directory test-coverage

clean:
	cargo clean
	rm -rf test-coverage

verify-cryptolspecs:
	CRYPTOLPATH=${CRYPTOLPATH} CRUX_MIR=crux-mir-comp cargo crux-test --lib -- ${COVERAGE} -s z3 -m compress_t1_equiv
	CRYPTOLPATH=${CRYPTOLPATH} CRUX_MIR=crux-mir-comp cargo crux-test --lib -- ${COVERAGE} -s z3 -m compress_t2_equiv
	CRYPTOLPATH=${CRYPTOLPATH} CRUX_MIR=crux-mir-comp cargo crux-test --lib -- ${COVERAGE} -s z3 -m message_schedule_one_equiv
# Functions below currently time out
# 	CRYPTOLPATH=${CRYPTOLPATH} CRUX_MIR=crux-mir-comp cargo crux-test --lib -- ${COVERAGE} -s z3 -m message_schedule_words_equiv
#	CRYPTOLPATH=${CRYPTOLPATH} CRUX_MIR=crux-mir-comp cargo crux-test --lib -- ${COVERAGE} -s z3 -m compress_words_equiv
# 	CRYPTOLPATH=${CRYPTOLPATH} CRUX_MIR=crux-mir-comp cargo crux-test --lib -- ${COVERAGE} -s z3 -m block_data_order_slice_words_equiv

verify-hacspecs:
	CRUX_MIR=crux-mir-comp cargo crux-test --lib -- ${COVERAGE} -s z3 -m ch_equiv
	CRUX_MIR=crux-mir-comp cargo crux-test --lib -- ${COVERAGE} -s z3 -m maj_equiv
	CRUX_MIR=crux-mir-comp cargo crux-test --lib -- ${COVERAGE} -s z3 -m SIGMA_0_equiv
	CRUX_MIR=crux-mir-comp cargo crux-test --lib -- ${COVERAGE} -s z3 -m SIGMA_1_equiv
	CRUX_MIR=crux-mir-comp cargo crux-test --lib -- ${COVERAGE} -s z3 -m sigma_0_equiv
	CRUX_MIR=crux-mir-comp cargo crux-test --lib -- ${COVERAGE} -s z3 -m sigma_1_equiv
	CRYPTOLPATH=${CRYPTOLPATH} CRUX_MIR=crux-mir-comp cargo crux-test --lib -- ${COVERAGE} -s z3 -m compress_t1_equiv
	CRYPTOLPATH=${CRYPTOLPATH} CRUX_MIR=crux-mir-comp cargo crux-test --lib -- ${COVERAGE} -s z3 -m compress_t2_equiv
	CRYPTOLPATH=${CRYPTOLPATH} CRUX_MIR=crux-mir-comp cargo crux-test --lib -- ${COVERAGE} -s z3 -m message_schedule_one_equiv
# Functions below currently time out
# 	CRYPTOLPATH=${CRYPTOLPATH} CRUX_MIR=crux-mir-comp cargo crux-test --lib -- ${COVERAGE} -s z3 -m compress_words_equiv
# 	CRYPTOLPATH=${CRYPTOLPATH} CRUX_MIR=crux-mir-comp cargo crux-test --lib -- ${COVERAGE} -s z3 -m message_schedule_words_equiv
# 	CRYPTOLPATH=${CRYPTOLPATH} CRUX_MIR=crux-mir-comp cargo crux-test --lib -- ${COVERAGE} -s z3 -m block_data_order_slice_words_equiv

# Coverage is currently disabled, until https://github.com/GaloisInc/crucible/issues/1534#issuecomment-4718780378 is resolved
#coverage:
#	find ./test-coverage -name 'report_data.js' | xargs cargo run --manifest-path ${COV_REP} --

patch:
	cd deps/hacspec && git apply ../hacspec.patch
