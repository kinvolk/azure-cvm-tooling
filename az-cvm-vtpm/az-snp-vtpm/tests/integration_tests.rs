#[cfg(feature = "integration_test")]
mod tests {
    use az_snp_vtpm::{hcl, report, vtpm};
    use serde::Deserialize;

    #[test]
    fn get_report_with_varying_report_data_len() {
        let mut report_data = "test".as_bytes();
        vtpm::get_report_with_report_data(report_data).unwrap();
        report_data = "test_test".as_bytes();
        vtpm::get_report_with_report_data(report_data).unwrap();
    }

    #[derive(Deserialize, Debug)]
    struct VarDataUserData {
        #[serde(rename = "user-data")]
        user_data: String,
    }

    #[test]
    fn get_report_with_report_data() {
        let mut report_data: [u8; 64] = [0; 64];
        report_data[42] = 42;
        let bytes = vtpm::get_report_with_report_data(&report_data).unwrap();
        let hcl_report = hcl::HclReport::new(bytes).unwrap();
        let var_data = hcl_report.var_data();
        let VarDataUserData { user_data } = serde_json::from_slice(var_data).unwrap();
        assert_eq!(user_data.to_lowercase(), hex::encode(report_data));

        let var_data_hash = hcl_report.var_data_sha256();
        let snp_report: report::AttestationReport = hcl_report.try_into().unwrap();
        assert_eq!(var_data_hash, snp_report.report_data[..32]);
    }

    #[test]
    fn get_report() {
        let bytes = vtpm::get_report().unwrap();
        let hcl_report = hcl::HclReport::new(bytes).unwrap();

        let var_data_hash = hcl_report.var_data_sha256();
        let snp_report: report::AttestationReport = hcl_report.try_into().unwrap();
        assert_eq!(var_data_hash, snp_report.report_data[..32]);
    }

    #[test]
    fn ak_pub() {
        let _ = vtpm::get_ak_pub().unwrap();
    }
}
