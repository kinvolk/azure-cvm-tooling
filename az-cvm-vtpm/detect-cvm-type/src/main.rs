// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use detect_cvm_type::detect;
use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
    let cvm_type = detect()?;
    println!("CVM type: {:?}", cvm_type);
    Ok(())
}
