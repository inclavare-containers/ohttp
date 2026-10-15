use crate::{err::Res, AeadId};

pub trait Decrypt {
    fn open(&mut self, aad: &[u8], ct: &[u8]) -> Res<Vec<u8>>;
    /// Decrypt `ct||tag`, held in `in_out`, in place, leaving the plaintext
    /// at the front of the same slice and returning its length.  Backends
    /// whose engine supports in-place open override this; the default calls
    /// `open` and copies the result back.
    ///
    /// On error the contents of `in_out` are unspecified.  Callers must
    /// treat the buffer as dead whenever `Err` is returned (the chunk
    /// stream aborts on failure and never hands the buffer onward), whereas
    /// `open` leaves its input untouched.
    #[allow(dead_code)] // Used by stream feature.
    fn open_in_place(&mut self, aad: &[u8], in_out: &mut [u8]) -> Res<usize> {
        let pt = self.open(aad, &*in_out)?;
        let len = pt.len();
        in_out[..len].copy_from_slice(&pt);
        Ok(len)
    }
    #[allow(dead_code)] // Used by stream feature.
    fn alg(&self) -> AeadId;
}

pub trait Encrypt {
    fn seal(&mut self, aad: &[u8], ct: &[u8]) -> Res<Vec<u8>>;
    /// Seal `pt` into `out`, overwriting its contents and (for backends
    /// that override this) reusing its allocation.  The default moves the
    /// result of `seal` into `out`, so non-overriding backends keep today's
    /// one-allocation-per-chunk cost with no extra copy.
    #[allow(dead_code)] // Used by stream feature.
    fn seal_into(&mut self, aad: &[u8], pt: &[u8], out: &mut Vec<u8>) -> Res<()> {
        *out = self.seal(aad, pt)?;
        Ok(())
    }
    #[allow(dead_code)] // Used by stream feature.
    fn alg(&self) -> AeadId;
}
