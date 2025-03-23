macro_rules! warn {
($($arg:tt)+) => {
        #[cfg(feature = "log")]
        log::warn!($($arg)+);
        #[cfg(feature = "defmt")]
        defmt::warn!($($arg)+);
    };
}

macro_rules! error {
($($arg:tt)+) => {
        #[cfg(feature = "log")]
        log::error!($($arg)+);
        #[cfg(feature = "defmt")]
        defmt::error!($($arg)+);
    };
}
