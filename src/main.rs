use std::collections::HashMap;

use base64::{Engine, prelude::BASE64_URL_SAFE_NO_PAD};
use curve25519_dalek::{
    Scalar,
    ristretto::{self, CompressedRistretto, RistrettoPoint},
};

use heidi_jwt::{
    JwsHeader,
    chrono::{self, Duration},
    jwt::{Jwt, creator::JwtCreator},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::Sha512;

fn main() {
    let mut rng = rand::thread_rng();
    let (g, h) = (
        RistrettoPoint::random(&mut rng),
        RistrettoPoint::random(&mut rng),
    );
    let sd_jwt1 = issue_sd_jwt(
        json!({
            "test" : "abc",
            "dob" : 1958
        }),
        g.clone(),
        h.clone(),
    );
    let sd_jwt2 = issue_sd_jwt(
        json!({
            "test" : "abce",
            "dob" : 1958
        }),
        g.clone(),
        h.clone(),
    );
    let proof =
        BASE64_URL_SAFE_NO_PAD.encode(prove_equality("dob", &sd_jwt1, &sd_jwt2, vec![]).as_bytes());
    let mut challenge_bytes = vec![];
    challenge_bytes.extend_from_slice("dob".as_bytes());
    challenge_bytes.extend_from_slice(g.compress().as_bytes());
    challenge_bytes.extend_from_slice(h.compress().as_bytes());

    let (jwt1, _) = sd_jwt1.split_once("~").unwrap();
    let (jwt2, _) = sd_jwt2.split_once("~").unwrap();

    let jwt1_parsed: Jwt<Value> = jwt1.parse().unwrap();
    let jwt2_parsed: Jwt<Value> = jwt2.parse().unwrap();
    let relevant_commitment = jwt1_parsed
        .payload_unverified()
        .insecure()
        .get("com_link")
        .unwrap()
        .get("dob")
        .unwrap()
        .clone()
        .as_u64()
        .unwrap();
    let com1 = jwt1_parsed
        .payload_unverified()
        .insecure()
        .get("_sd")
        .unwrap()
        .get(relevant_commitment as usize)
        .unwrap()
        .as_str()
        .unwrap()
        .to_string();
    let com2 = jwt2_parsed
        .payload_unverified()
        .insecure()
        .get("_sd")
        .unwrap()
        .get(relevant_commitment as usize)
        .unwrap()
        .as_str()
        .unwrap()
        .to_string();

    let zk_proof = ZkProof {
        inputs: vec![
            Input::Private {
                path: "dob".to_string(),
                value: com1.clone(),
            },
            Input::Private {
                path: "dob".to_string(),
                value: com2.clone(),
            },
        ],
        system: vec![1, -1],
        context: BASE64_URL_SAFE_NO_PAD.encode(challenge_bytes),
        proof: proof,
        proof_type: ProofType::Equality,
    };

    let sd_hash1 = BASE64_URL_SAFE_NO_PAD
        .encode(Scalar::hash_from_bytes::<Sha512>(format!("{}~", jwt1).as_bytes()).as_bytes());
    let sd_hash2 = BASE64_URL_SAFE_NO_PAD
        .encode(Scalar::hash_from_bytes::<Sha512>(format!("{}~", jwt2).as_bytes()).as_bytes());
    let mut jws_header = JwsHeader::new();
    jws_header.set_token_type("kb+jwt");
    jws_header.set_algorithm(heidi_jwt::ES256.name());
    let kp = heidi_jwt::ES256.generate_key_pair().unwrap();
    let signer = heidi_jwt::ES256
        .signer_from_jwk(&kp.to_jwk_key_pair())
        .unwrap();
    let kb_jwt1 = json!({
        "nonce": "nonce",
        "aud": "proofer",
        "sd_hash": sd_hash1,
        "proofs": [
            zk_proof
        ]
    })
    .create_jwt(&jws_header, None, chrono::Duration::minutes(5), &signer)
    .unwrap();
    let kb_jwt2 = json!({
        "nonce": "nonce",
        "aud": "proofer",
        "sd_hash": sd_hash2,
        "proofs": [
            zk_proof
        ]
    })
    .create_jwt(&jws_header, None, chrono::Duration::minutes(5), &signer)
    .unwrap();
    println!("Presentation 1: {}~{}", jwt1, kb_jwt1);
    println!("Presentation 2: {}~{}", jwt2, kb_jwt2);

    let proof_value =
        EqualityProof::from_bytes(&BASE64_URL_SAFE_NO_PAD.decode(zk_proof.proof).unwrap());

    let proof_verify = proof_value.verify(
        BASE64_URL_SAFE_NO_PAD.decode(zk_proof.context).unwrap(),
        &com1,
        &com2,
    );

    println!("Proof Verification: {}", proof_verify);
}
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ZkProof {
    inputs: Vec<Input>,
    system: Vec<i8>,
    context: String,
    proof: String,
    proof_type: ProofType,
}
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum ProofType {
    #[serde(rename = "equality_proof")]
    Equality,
}

struct EqualityProof {
    g: RistrettoPoint,
    h: RistrettoPoint,
    s1: Scalar,
    r1: Scalar,
    s2: Scalar,
    r2: Scalar,
    com1: RistrettoPoint,
    com2: RistrettoPoint,
}

impl EqualityProof {
    pub fn verify(&self, context: Vec<u8>, c1: &str, c2: &str) -> bool {
        let c1 = CompressedRistretto::from_slice(&BASE64_URL_SAFE_NO_PAD.decode(c1).unwrap())
            .unwrap()
            .decompress()
            .unwrap();
        let c2 = CompressedRistretto::from_slice(&BASE64_URL_SAFE_NO_PAD.decode(c2).unwrap())
            .unwrap()
            .decompress()
            .unwrap();

        let challenge = Scalar::hash_from_bytes::<Sha512>(&context);

        let verify1 = self.s1 * self.g + self.r1 * self.h + challenge * c1;
        let verify2 = self.s2 * self.g + self.r2 * self.h + challenge * c2;
        println!("{}", verify1 == self.com1);
        println!("{}", verify2 == self.com2);
        println!("{}", self.s1 == self.s2);
        verify1 == self.com1 && verify2 == self.com2 && self.s1 == self.s2
    }
    pub fn as_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        bytes.extend_from_slice(&self.s1.to_bytes());
        bytes.extend_from_slice(&self.r1.to_bytes());
        bytes.extend_from_slice(&self.s2.to_bytes());
        bytes.extend_from_slice(&self.r2.to_bytes());
        bytes.extend_from_slice(self.com1.compress().as_bytes());
        bytes.extend_from_slice(self.com2.compress().as_bytes());
        bytes.extend_from_slice(self.g.compress().as_bytes());
        bytes.extend_from_slice(self.h.compress().as_bytes());
        bytes
    }
    pub fn from_bytes(bytes: &[u8]) -> Self {
        let s1 = Scalar::from_bytes_mod_order(bytes[0..32].try_into().unwrap());
        let r1 = Scalar::from_bytes_mod_order(bytes[32..64].try_into().unwrap());
        let s2 = Scalar::from_bytes_mod_order(bytes[64..96].try_into().unwrap());
        let r2 = Scalar::from_bytes_mod_order(bytes[96..128].try_into().unwrap());
        let com1 = CompressedRistretto::from_slice(bytes[128..160].try_into().unwrap())
            .unwrap()
            .decompress()
            .unwrap();
        let com2 = CompressedRistretto::from_slice(bytes[160..192].try_into().unwrap())
            .unwrap()
            .decompress()
            .unwrap();
        let g = CompressedRistretto::from_slice(bytes[192..224].try_into().unwrap())
            .unwrap()
            .decompress()
            .unwrap();
        let h = CompressedRistretto::from_slice(bytes[224..256].try_into().unwrap())
            .unwrap()
            .decompress()
            .unwrap();
        EqualityProof {
            g,
            h,
            s1,
            r1,
            s2,
            r2,
            com1,
            com2,
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum Input {
    Public { public_value: Value },
    Private { path: String, value: String },
}
fn presentation(sd_jwt: &str, disclosures: Vec<String>, zk_proof: ZkProof) -> String {
    todo! {}
}

fn prove_equality(attr: &str, sd_jwt1: &str, sd_jwt2: &str, nonce: Vec<u8>) -> EqualityProof {
    let mut rng = rand::thread_rng();
    let (jwt1, rest1) = sd_jwt1.split_once("~").unwrap();
    let (jwt2, rest2) = sd_jwt2.split_once("~").unwrap();
    let disclosures1 = rest1
        .split("~")
        .map(|a| {
            let dis = BASE64_URL_SAFE_NO_PAD.decode(a).unwrap();
            let el: Value = serde_json::from_slice(&dis).unwrap();
            let blinding = el.get(0).unwrap().as_str().unwrap().to_string();
            let val = el.get(2).unwrap().clone();
            let attr = el.get(1).unwrap().as_str().unwrap().to_string();
            (attr, (blinding, val))
        })
        .collect::<HashMap<_, _>>();
    let disclosures2 = rest2
        .split("~")
        .map(|a| {
            let dis = BASE64_URL_SAFE_NO_PAD.decode(a).unwrap();
            let el: Value = serde_json::from_slice(&dis).unwrap();
            let blinding = el.get(0).unwrap().as_str().unwrap().to_string();
            let val = el.get(2).unwrap().clone();
            let attr = el.get(1).unwrap().as_str().unwrap().to_string();
            (attr, (blinding, val))
        })
        .collect::<HashMap<_, _>>();

    let dis1 = disclosures1.get(attr).unwrap().clone();
    let dis2 = disclosures2.get(attr).unwrap().clone();
    let mut blinding1_bytes: [u8; 32] = [0; 32];
    blinding1_bytes.copy_from_slice(&BASE64_URL_SAFE_NO_PAD.decode(dis1.0).unwrap());
    let blinding1 = Scalar::from_bytes_mod_order(blinding1_bytes);
    let mut blinding2_bytes: [u8; 32] = [0; 32];
    blinding2_bytes.copy_from_slice(&BASE64_URL_SAFE_NO_PAD.decode(dis2.0).unwrap());
    let blinding2 = Scalar::from_bytes_mod_order(blinding2_bytes);

    let value1 = match dis1.1 {
        Value::Number(number) => {
            let scalar_number = number.as_i64().unwrap();
            if scalar_number >= 0 {
                Scalar::from(scalar_number.abs() as u64)
            } else {
                Scalar::from(scalar_number.abs() as u64).invert()
            }
        }
        _ => {
            let serialized_value = serde_json::to_string(&dis1.1).unwrap();
            Scalar::hash_from_bytes::<Sha512>(serialized_value.as_bytes())
        }
    };
    let value2 = match dis2.1 {
        Value::Number(number) => {
            let scalar_number = number.as_i64().unwrap();
            if scalar_number >= 0 {
                Scalar::from(scalar_number.abs() as u64)
            } else {
                Scalar::from(scalar_number.abs() as u64).invert()
            }
        }
        _ => {
            let serialized_value = serde_json::to_string(&dis2.1).unwrap();
            Scalar::hash_from_bytes::<Sha512>(serialized_value.as_bytes())
        }
    };

    let jwt1: Jwt<Value> = jwt1.parse().unwrap();
    let jwt2: Jwt<Value> = jwt2.parse().unwrap();
    let relevant_commitment = jwt1
        .payload_unverified()
        .insecure()
        .get("com_link")
        .unwrap()
        .get(attr)
        .unwrap()
        .clone()
        .as_u64()
        .unwrap();
    let com1 = jwt1
        .payload_unverified()
        .insecure()
        .get("_sd")
        .unwrap()
        .get(relevant_commitment as usize)
        .unwrap()
        .as_str()
        .unwrap()
        .to_string();
    let com2 = jwt2
        .payload_unverified()
        .insecure()
        .get("_sd")
        .unwrap()
        .get(relevant_commitment as usize)
        .unwrap()
        .as_str()
        .unwrap()
        .to_string();
    let com1 = BASE64_URL_SAFE_NO_PAD.decode(&com1).unwrap();
    let com2 = BASE64_URL_SAFE_NO_PAD.decode(&com2).unwrap();
    let com1 = CompressedRistretto::from_slice(&com1)
        .unwrap()
        .decompress()
        .unwrap();
    let com2 = CompressedRistretto::from_slice(&com2)
        .unwrap()
        .decompress()
        .unwrap();

    let g = jwt1
        .payload_unverified()
        .insecure()
        .get("_sd_alg_param")
        .unwrap()
        .get("commitment_scheme")
        .unwrap()
        .get("public_params")
        .unwrap()
        .get("g")
        .unwrap()
        .as_str()
        .unwrap()
        .to_string();
    let h = jwt1
        .payload_unverified()
        .insecure()
        .get("_sd_alg_param")
        .unwrap()
        .get("commitment_scheme")
        .unwrap()
        .get("public_params")
        .unwrap()
        .get("h")
        .unwrap()
        .as_str()
        .unwrap()
        .to_string();
    let g = BASE64_URL_SAFE_NO_PAD.decode(g).unwrap();
    let h = BASE64_URL_SAFE_NO_PAD.decode(h).unwrap();
    let mut challenge_bytes = vec![];
    challenge_bytes.extend_from_slice(attr.as_bytes());
    challenge_bytes.extend_from_slice(&g);
    challenge_bytes.extend_from_slice(&h);
    challenge_bytes.extend_from_slice(&nonce);

    let g = CompressedRistretto::from_slice(&g)
        .unwrap()
        .decompress()
        .unwrap();
    let h = CompressedRistretto::from_slice(&h)
        .unwrap()
        .decompress()
        .unwrap();
    let rand_x1 = Scalar::random(&mut rng);
    let rand_y1 = Scalar::random(&mut rng);
    let random_com1 = rand_x1 * g + rand_y1 * h;

    let rand_x2 = Scalar::random(&mut rng);
    let rand_y2 = Scalar::random(&mut rng);
    let random_com2 = rand_x1 * g + rand_y2 * h;
    let challenge = Scalar::hash_from_bytes::<Sha512>(&challenge_bytes);

    let s1 = rand_x1 - challenge * value1;
    let r1 = rand_y1 - challenge * blinding1;
    let s2 = rand_x1 - challenge * value2;
    let r2 = rand_y2 - challenge * blinding2;
    let c1 = s1 * g + r1 * h + challenge * com1;
    let c2 = s2 * g + r2 * h + challenge * com2;
    println!("First: {}", c1 == random_com1);
    println!("Second: {}", c2 == random_com2);
    println!("Relation: {}", s1 == s2);

    EqualityProof {
        g,
        h,
        s1,
        r1,
        s2,
        r2,
        com1: random_com1,
        com2: random_com2,
    }
}

fn issue_sd_jwt(claims: Value, g: RistrettoPoint, h: RistrettoPoint) -> String {
    let mut rng = rand::thread_rng();

    let mut disclosures = vec![];
    let mut sds = vec![];

    for c in claims.as_object().unwrap() {
        match c.1 {
            Value::Number(number) => {
                let scalar_number = number.as_i64().unwrap();
                let s = if scalar_number >= 0 {
                    Scalar::from(scalar_number.abs() as u64)
                } else {
                    Scalar::from(scalar_number.abs() as u64).invert()
                };
                let blinding = Scalar::random(&mut rng);
                let blinding_bytes = BASE64_URL_SAFE_NO_PAD.encode(blinding.as_bytes());

                let commitment = s * g + blinding * h;
                let b = BASE64_URL_SAFE_NO_PAD.encode(commitment.compress().as_bytes());
                let mut disclosure_array = vec![];
                disclosure_array.push(Value::String(blinding_bytes));
                disclosure_array.push(Value::String(c.0.to_string()));
                disclosure_array.push(c.1.clone());
                disclosures.push(Value::Array(disclosure_array));
                sds.push(Value::String(b));
            }
            _ => {
                let serialized_value = serde_json::to_string(&c.1).unwrap();
                let scalar_hash = Scalar::hash_from_bytes::<Sha512>(serialized_value.as_bytes());
                let blinding = Scalar::random(&mut rng);
                let blinding_bytes = BASE64_URL_SAFE_NO_PAD.encode(blinding.as_bytes());

                let commitment = scalar_hash * g + blinding * h;
                let b = BASE64_URL_SAFE_NO_PAD.encode(commitment.compress().as_bytes());
                let mut disclosure_array = vec![];
                disclosure_array.push(Value::String(blinding_bytes));
                disclosure_array.push(Value::String(c.0.to_string()));
                disclosure_array.push(c.1.clone());
                disclosures.push(Value::Array(disclosure_array));
                sds.push(Value::String(b));
            }
        }
    }
    let body = json!({
        "_sd" : sds,
        "_sd_alg" : "ec_pedersen",
        "_sd_alg_param" : {
            "commitment_scheme" : {
                "public_params" : {
                    "g" : BASE64_URL_SAFE_NO_PAD.encode(g.compress().as_bytes()),
                    "h" : BASE64_URL_SAFE_NO_PAD.encode(h.compress().as_bytes()),
                },
                "crv": "ed25519"
            }
        },
        "com_link" :{
            "test" : 0,
            "dob" : 1
        }
    });
    let signer = heidi_jwt::ES256.generate_key_pair().unwrap();
    let signer = heidi_jwt::ES256
        .signer_from_jwk(&signer.to_jwk_key_pair())
        .unwrap();
    let mut jws_header = JwsHeader::new();
    jws_header.set_algorithm(heidi_jwt::ES256.name());
    let jwt_part = body
        .create_jwt(
            &jws_header,
            Some("sample_issuer"),
            Duration::minutes(6),
            &signer,
        )
        .unwrap();
    let disclosures = disclosures
        .into_iter()
        .map(|a| BASE64_URL_SAFE_NO_PAD.encode(serde_json::to_string(&a).unwrap()))
        .collect::<Vec<String>>()
        .join("~");
    format!("{}~{}", jwt_part, disclosures)
}
