use crate::results::{CheckStatus, CheckerResult};
use crate::system_access::SystemAccess;
use serde::Deserialize;

// Bottlerocket doesn't use the standard path for most of these files ¯\_(ツ)_/¯
pub const KUBELET_SERVICE_FILE: &str = "/etc/systemd/system/kubelet.service.d/exec-start.conf";
pub const KUBELET_KUBECONFIG_FILE: &str = "/etc/kubernetes/kubelet/kubeconfig";
pub const KUBELET_CLIENT_CA_FILE: &str = "/etc/kubernetes/pki/ca.crt";
pub const KUBELET_CONF_FILE: &str = "/etc/kubernetes/kubelet/config";
pub const KUBEPROXY_CONF_FILE: &str = "/etc/kubernetes/kube-proxy/kube-proxy.conf";
pub const KUBEPROXY_KUBECONFIG_FILE: &str = "/etc/kubernetes/kube-proxy/kubeconfig";
pub const KUBELET_CONFIG_DIR: &str = "/etc/kubernetes/kubelet/";
pub const KUBELET_PKI_DIR: &str = "/etc/kubernetes/pki/";
pub const KUBERNETES_MANIFESTS_DIR: &str = "/etc/kubernetes/manifests/";

// Some of the checks are identical between the Kubernetes CIS benchmark and Kubernetes STIG. Modifying
// these functions requires validating against both the CIS and STIG to ensure that the changes are
// valid for both.

pub fn ensure_kubelet_readonly_port_disabled(sac: &dyn SystemAccess) -> CheckerResult {
    #[derive(Deserialize)]
    struct KubeletConfig {
        #[serde(rename = "readOnlyPort")]
        read_only_port: i32,
    }

    let mut result = CheckerResult::default();

    if let Ok(kubelet_file) = sac.open(KUBELET_CONF_FILE) {
        if let Ok(config) = serde_yaml::from_reader::<_, KubeletConfig>(kubelet_file) {
            if config.read_only_port != 0 {
                result.error = "Kubelet readOnlyPort not set to 0".to_string();
                result.status = CheckStatus::FAIL;
            } else {
                result.status = CheckStatus::PASS;
            }
        } else {
            result.error = "unable to parse kubelet config".to_string()
        }
    } else {
        result.error = format!("unable to read '{KUBELET_CONF_FILE}'");
    }

    result
}

pub fn ensure_kubelet_anonymous_auth_disabled(sac: &dyn SystemAccess) -> CheckerResult {
    #[derive(Deserialize)]
    struct Anonymous {
        enabled: bool,
    }

    #[derive(Deserialize)]
    struct Authentication {
        anonymous: Anonymous,
    }

    #[derive(Deserialize)]
    struct KubeletConfig {
        authentication: Authentication,
    }

    let mut result = CheckerResult::default();

    if let Ok(kubelet_file) = sac.open(KUBELET_CONF_FILE) {
        if let Ok(config) = serde_yaml::from_reader::<_, KubeletConfig>(kubelet_file) {
            if config.authentication.anonymous.enabled {
                result.error = "anonymous authentication is configured".to_string();
                result.status = CheckStatus::FAIL;
            } else {
                result.status = CheckStatus::PASS;
            }
        } else {
            result.error = "unable to parse kubelet config".to_string()
        }
    } else {
        result.error = format!("unable to read '{KUBELET_CONF_FILE}'");
    }

    result
}

pub fn ensure_kubelet_client_ca_configured(sac: &dyn SystemAccess) -> CheckerResult {
    #[derive(Deserialize)]
    struct X509 {
        #[serde(rename = "clientCAFile")]
        client_ca_file: String,
    }

    #[derive(Deserialize)]
    struct Authentication {
        x509: X509,
    }

    #[derive(Deserialize)]
    struct KubeletConfig {
        authentication: Authentication,
    }

    let mut result = CheckerResult::default();

    if let Ok(kubelet_file) = sac.open(KUBELET_CONF_FILE) {
        if let Ok(config) = serde_yaml::from_reader::<_, KubeletConfig>(kubelet_file) {
            if !config.authentication.x509.client_ca_file.is_empty()
                && sac.exists(&config.authentication.x509.client_ca_file)
            {
                result.status = CheckStatus::PASS;
            } else {
                result.error = "CA file not set to expected path".to_string();
                result.status = CheckStatus::FAIL;
            }
        } else {
            result.error = "unable to parse kubelet config".to_string()
        }
    } else {
        result.error = format!("unable to read '{KUBELET_CONF_FILE}'");
    }

    result
}

pub fn ensure_kubelet_private_key_set(sac: &dyn SystemAccess) -> CheckerResult {
    #[derive(Deserialize)]
    struct KubeletConfig {
        #[serde(rename = "tlsPrivateKeyFile")]
        tls_private_key_file: String,
    }

    let mut result = CheckerResult::default();

    if let Ok(kubelet_file) = sac.open(KUBELET_CONF_FILE) {
        if let Ok(config) = serde_yaml::from_reader::<_, KubeletConfig>(kubelet_file) {
            if !config.tls_private_key_file.is_empty() && sac.exists(&config.tls_private_key_file) {
                result.status = CheckStatus::PASS;
            } else {
                result.error = "TLS private key files not set to expected path".to_string();
                result.status = CheckStatus::FAIL;
            }
        } else {
            // If certs not provided then `serverTLSBootstrap` will be used. Deserialization expected to fail in this case.
            result.status = CheckStatus::PASS;
        }
    } else {
        result.error = format!("unable to read '{KUBELET_CONF_FILE}'");
    }
    result
}

pub fn ensure_kubelet_private_cert_set(sac: &dyn SystemAccess) -> CheckerResult {
    #[derive(Deserialize)]
    struct KubeletConfig {
        #[serde(rename = "tlsCertFile")]
        tls_cert_file: String,
    }

    let mut result = CheckerResult::default();

    if let Ok(kubelet_file) = sac.open(KUBELET_CONF_FILE) {
        if let Ok(config) = serde_yaml::from_reader::<_, KubeletConfig>(kubelet_file) {
            if !config.tls_cert_file.is_empty() && sac.exists(&config.tls_cert_file) {
                result.status = CheckStatus::PASS;
            } else {
                result.error = "TLS private cert file not set to expected path".to_string();
                result.status = CheckStatus::FAIL;
            }
        } else {
            // If certs not provided then `serverTLSBootstrap` will be used. Deserialization expected to fail in this case.
            result.status = CheckStatus::PASS;
        }
    } else {
        result.error = format!("unable to read '{KUBELET_CONF_FILE}'");
    }
    result
}
