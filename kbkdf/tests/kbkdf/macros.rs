macro_rules! test_counter_mode {
    ($name:ident, $prf:ty, $out_len:ty, $r:ty, $test_cases:expr) => {
        #[test]
        fn $name() {
            for test_case in $test_cases {
                let counter = kbkdf::Counter::<$prf, $out_len, $r>::default();

                let key = counter
                    .derive(
                        test_case.kin,
                        false,
                        false,
                        test_case.label,
                        test_case.context,
                    )
                    .unwrap();

                assert_eq!(test_case.kout[..], key[..]);
            }
        }
    };
}

macro_rules! test_feedback_mode_iv {
    ($name:ident, $prf:ty, $out_len:ty, $r:ty, $test_cases:expr) => {
        #[test]
        fn $name() {
            for test_case in $test_cases {
                let feedback = kbkdf::Feedback::<$prf, $out_len, $r>::new(Some(test_case.iv.into()));

                let key = feedback
                    .derive(
                        test_case.kin,
                        false,
                        false,
                        test_case.label,
                        test_case.context,
                    )
                    .unwrap();

                assert_eq!(test_case.kout[..], key[..]);
            }
        }
    };
}
