extern crate rustc_serialize;

use rustc_serialize::base64::FromBase64;

pub struct JWT {
    header: String,
    payload: String,
    signature: String
}


pub fn new(input: &str) -> Result<JWT, String>{
    let mut jwt = JWT{header: "".to_string(), payload: "".to_string(), signature: "".to_string()};
    let jwt_parts: Vec<&str> = input.split(".").collect();
    if jwt_parts.len() != 3 {
        return Err("Malformed JWT".to_string());
    }
    jwt.header = match decode(jwt_parts[0]) {
        Ok(s) => s,
        Err(_) => return Err("Error decoding header".to_string()),
    };
    jwt.payload= match decode(jwt_parts[1]) {
        Ok(s) => s,
        Err(_) => return Err("Error decoding payload".to_string()),
    };
    jwt.signature = jwt_parts[2].to_owned();
    Ok(jwt)
}

fn decode(input: &str) -> Result<String, String> {
    let bytes = match input.from_base64() {
        Ok(s) => s,
        Err(_) => return Err("Error decoding".to_string()),
    };
    let decoded = match String::from_utf8(bytes) {
        Ok(s) => s,
        Err(_) => return Err("Error from utf8".to_string()),
    };
    Ok(decoded)
}


#[cfg(test)]
mod test {

    use super::new;
    use super::decode;

    #[test]
    fn test_new() {
        let jwt_input = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiw\
             ibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.TJVA95OrM7E2cBab30RMHr\
             HDcEfxjoYZgeFONFh7HgQ".to_string();

        // Expected outcomes
        let header = "{\"alg\":\"HS256\",\
                      \"typ\":\"JWT\"}";
        let payload = "{\"sub\":\"1234567890\",\
                       \"name\":\"John Doe\",\
                       \"admin\":true}";

        let jwt = new(&jwt_input).unwrap();

        assert_eq!(header, jwt.header);
        assert_eq!(payload, jwt.payload);
    }

    #[test]
    fn test_new_malformed() {
        let input = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";
        let jwt = new(&input);
        assert!(jwt.is_err());
    }

    #[test]
    fn test_new_empty() {
        let input = "";
        let jwt = new(&input);
        assert!(jwt.is_err());
    }

    #[test]
    fn test_decode() {
        let to_decode = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";
        let expected = "{\"alg\":\"HS256\",\
                      \"typ\":\"JWT\"}";
        let decoded = decode(&to_decode).unwrap();
        assert_eq!(expected, decoded);
    }
}
