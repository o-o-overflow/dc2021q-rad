//! Array serialization helpers.

use crate::data::Bytes;
use serde::de::{SeqAccess, Visitor};
use serde::ser::{SerializeStruct, SerializeTuple};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::marker::PhantomData;

pub trait BigArray<'de>: Sized {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer;
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>;
}

macro_rules! big_array {
    ($($len:expr,)+) => {
        $(
            impl<'de, T> BigArray<'de> for [T; $len]
                where T: Default + Copy + Serialize + Deserialize<'de>
            {
                fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
                    where S: Serializer
                {
                    let mut seq = serializer.serialize_tuple(self.len())?;
                    for elem in &self[..] {
                        seq.serialize_element(elem)?;
                    }
                    seq.end()
                }

                fn deserialize<D>(deserializer: D) -> Result<[T; $len], D::Error>
                    where D: Deserializer<'de>
                {
                    struct ArrayVisitor<T> {
                        element: PhantomData<T>,
                    }

                    impl<'de, T> Visitor<'de> for ArrayVisitor<T>
                        where T: Default + Copy + Deserialize<'de>
                    {
                        type Value = [T; $len];

                        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                            formatter.write_str(concat!("an array of length ", $len))
                        }

                        fn visit_seq<A>(self, mut seq: A) -> Result<[T; $len], A::Error>
                            where A: SeqAccess<'de>
                        {
                            let mut arr = [T::default(); $len];
                            for i in 0..$len {
                                arr[i] = seq.next_element()?
                                    .ok_or_else(|| serde::de::Error::invalid_length(i, &self))?;
                            }
                            Ok(arr)
                        }
                    }

                    let visitor = ArrayVisitor { element: PhantomData };
                    deserializer.deserialize_tuple($len, visitor)
                }
            }
        )+
    }
}

impl<const N: usize> Serialize for Bytes<N> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("Bytes", 3)?;
        state.serialize_field("n", &N)?;
        let mut data = vec![];
        for xs in &self.data {
            data.extend_from_slice(xs);
        }
        state.serialize_field("data", &data)?;
        state.serialize_field("checksum", &self.checksum)?;
        state.end()
    }
}

impl<'de, const M: usize> Deserialize<'de> for Bytes<M> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(field_identifier, rename_all = "lowercase")]
        enum Field {
            N,
            Data,
            Checksum,
        }

        struct BytesVisitor<const M: usize>;

        impl<'de, const N: usize> Visitor<'de> for BytesVisitor<N> {
            type Value = Bytes<N>;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("struct Bytes<N>")
            }

            fn visit_seq<V>(self, mut seq: V) -> Result<Bytes<N>, V::Error>
            where
                V: SeqAccess<'de>,
            {
                let n = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(0, &self))?;
                let data: Vec<_> = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(1, &self))?;
                if data.len() != n * 3 {
                    return Err(serde::de::Error::invalid_length(n, &self));
                }
                let checksum = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(2, &self))?;
                let mut shards = [[0u8; N], [0u8; N], [0u8; N]];
                shards[0].copy_from_slice(&data[..N]);
                shards[1].copy_from_slice(&data[N..(2 * N)]);
                shards[2].copy_from_slice(&data[(2 * N)..]);
                Ok(Bytes {
                    data: shards,
                    checksum,
                })
            }
        }

        const FIELDS: &[&str] = &["n", "data", "checksum"];
        deserializer.deserialize_struct("Bytes", FIELDS, BytesVisitor)
    }
}

big_array! { 64, 4096, }
