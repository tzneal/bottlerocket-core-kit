use bloodhound::kubernetes::*;
use bloodhound::results::{CheckStatus, Checker, CheckerMetadata, CheckerResult, Mode};
use bloodhound::system_access::SystemAccess;
use bloodhound::{
    check_file_not_mode, check_output_contains, ensure_file_owner_and_group_root,
    look_for_strings_in_output,
};
use libc::{S_IRWXG, S_IRWXO, S_IWGRP, S_IWOTH, S_IXGRP, S_IXOTH, S_IXUSR};
use serde::Deserialize;
use std::time::Duration;
const SYSTEMCTL_CMD: &str = "/usr/bin/systemctl";

// =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<=
pub struct STIGV242387Checker {}

impl Checker for STIGV242387Checker {
    fn metadata(&self) -> CheckerMetadata {
        CheckerMetadata {
            title: "The Kubernetes Kubelet must have the \"readOnlyPort\" flag disabled."
                .to_string(),
            id: "V-242387".to_string(),
            level: 1,
            name: "k8sstigv242387".to_string(),
            mode: Mode::Automatic,
        }
    }

    fn execute(&self, sac: &dyn SystemAccess) -> CheckerResult {
        ensure_kubelet_readonly_port_disabled(sac)
    }
}

// =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<=
pub struct STIGV242391Checker {}
impl Checker for STIGV242391Checker {
    fn metadata(&self) -> CheckerMetadata {
        CheckerMetadata {
            title: "The Kubernetes Kubelet must have anonymous authentication disabled."
                .to_string(),
            id: "V-242391".to_string(),
            level: 1,
            name: "k8sstigv242391".to_string(),
            mode: Mode::Automatic,
        }
    }

    fn execute(&self, sac: &dyn SystemAccess) -> CheckerResult {
        ensure_kubelet_anonymous_auth_disabled(sac)
    }
}

// =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<=
pub struct STIGV242392Checker {}
impl Checker for STIGV242392Checker {
    fn metadata(&self) -> CheckerMetadata {
        CheckerMetadata {
            title: "The Kubernetes kubelet must enable explicit authorization.".to_string(),
            id: "V-242392".to_string(),
            level: 1,
            name: "k8sstigv242392".to_string(),
            mode: Mode::Automatic,
        }
    }

    fn execute(&self, sac: &dyn SystemAccess) -> CheckerResult {
        #[derive(Deserialize)]
        struct Authorization {
            mode: String,
        }

        #[derive(Deserialize)]
        struct KubeletConfig {
            authorization: Authorization,
        }

        let mut result = CheckerResult::default();

        if let Ok(kubelet_file) = sac.open(KUBELET_CONF_FILE) {
            if let Ok(config) = serde_yaml::from_reader::<_, KubeletConfig>(kubelet_file) {
                if config.authorization.mode != "Webhook" {
                    result.error = "Authorization mode not configured as Webhook".to_string();
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
}

// =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<=
pub struct STIGV242393Checker {}
impl Checker for STIGV242393Checker {
    fn metadata(&self) -> CheckerMetadata {
        CheckerMetadata {
            title: "Kubernetes Worker Nodes must not have sshd service running.".to_string(),
            id: "V-242393".to_string(),
            level: 2,
            name: "k8sstigv242393".to_string(),
            mode: Mode::Automatic,
        }
    }

    fn execute(&self, sac: &dyn SystemAccess) -> CheckerResult {
        check_output_contains!(
            sac,
            SYSTEMCTL_CMD,
            &["show", "--property", "ActiveState", "sshd"],
            &["ActiveState=inactive"],
            "unable to verify sshd service is not active",
            "sshd service is active"
        )
    }
}

// =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<=
pub struct STIGV242397Checker {}
impl Checker for STIGV242397Checker {
    fn metadata(&self) -> CheckerMetadata {
        CheckerMetadata {
            title: "The Kubernetes kubelet staticPodPath must not enable static pods.".to_string(),
            id: "V-242397".to_string(),
            level: 1,
            name: "k8sstigv242397".to_string(),
            mode: Mode::Automatic,
        }
    }

    fn execute(&self, sac: &dyn SystemAccess) -> CheckerResult {
        #[derive(Deserialize)]
        struct KubeletConfig {
            #[serde(rename = "staticPodPath")]
            static_pod_path: String,
        }

        let mut result = CheckerResult::default();

        if let Ok(kubelet_file) = sac.open(KUBELET_CONF_FILE) {
            if let Ok(config) = serde_yaml::from_reader::<_, KubeletConfig>(kubelet_file) {
                if !config.static_pod_path.is_empty() {
                    result.error = "staticPodPath must be empty".to_string();
                    result.status = CheckStatus::FAIL;
                } else {
                    result.status = CheckStatus::PASS;
                }
            } else {
                // The default for staticPodPath is unset, so it's fine for deserialization to fail
                result.status = CheckStatus::PASS;
            }
        } else {
            result.error = format!("unable to read '{KUBELET_CONF_FILE}'");
        }

        result
    }
}

// =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<=
pub struct STIGV242399Checker {}
impl Checker for STIGV242399Checker {
    fn metadata(&self) -> CheckerMetadata {
        CheckerMetadata {
            title: "Kubernetes DynamicKubeletConfig must not be enabled.".to_string(),
            id: "V-242399".to_string(),
            level: 2,
            name: "k8sstigv242399".to_string(),
            mode: Mode::Automatic,
        }
    }

    fn execute(&self, _: &dyn SystemAccess) -> CheckerResult {
        // DynamicKubeletConfig was removed in Kubernetes 1.24 and 
        // Bottlerocket no longer ships a 1.23 Kubelet 
        // https://kubernetes.io/blog/2018/07/11/dynamic-kubelet-configuration/
        CheckerResult{
            status: CheckStatus::PASS,
            ..Default::default()
        }
    }
}
// =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<=
pub struct STIGV242406Checker {}
impl Checker for STIGV242406Checker {
    fn metadata(&self) -> CheckerMetadata {
        CheckerMetadata {
            title: "The Kubernetes KubeletConfiguration file must be owned by root.".to_string(),
            id: "V-242406".to_string(),
            level: 2,
            name: "k8sstigv242406".to_string(),
            mode: Mode::Automatic,
        }
    }

    fn execute(&self, sac: &dyn SystemAccess) -> CheckerResult {
        let mut result = CheckerResult {
            status: CheckStatus::PASS,
            ..Default::default()
        };

        for entry in sac.walk_dir(KUBELET_CONFIG_DIR) {
            if entry.metadata.uid != 0 || entry.metadata.gid != 0 {
                result.error = format!(
                    "file {:?} has non-root ownership ({}:{})",
                    entry.path, entry.metadata.uid, entry.metadata.gid
                );
                result.status = CheckStatus::FAIL;
                break;
            }
        }
        result
    }
}

// =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<=
pub struct STIGV242407Checker {}
impl Checker for STIGV242407Checker {
    fn metadata(&self) -> CheckerMetadata {
        CheckerMetadata {
            title: "The Kubernetes KubeletConfiguration files must have file permissions set to 644 or more restrictive.".to_string(),
            id: "V-242407".to_string(),
            level: 2,
            name: "k8sstigv242407".to_string(),
            mode: Mode::Automatic,
        }
    }

    fn execute(&self, sac: &dyn SystemAccess) -> CheckerResult {
        let mut result = CheckerResult {
            status: CheckStatus::PASS,
            ..Default::default()
        };

        for entry in sac.walk_dir(KUBELET_CONFIG_DIR) {
            if !entry.metadata.is_file() {
                continue;
            }
            let no_x_xw_xw = S_IXUSR | S_IXGRP | S_IWGRP | S_IXOTH | S_IWOTH;
            if (entry.metadata.mode & no_x_xw_xw as u32) > 0 {
                result.error = format!("file {:?} has invalid permissions", entry.path);
                result.status = CheckStatus::FAIL;
                break;
            }
        }
        result
    }
}

// =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<=
pub struct STIGV242420Checker {}
impl Checker for STIGV242420Checker {
    fn metadata(&self) -> CheckerMetadata {
        CheckerMetadata {
            title: "Kubernetes Kubelet must have the SSL Certificate Authority set.".to_string(),
            id: "V-242420".to_string(),
            level: 2,
            name: "k8sstigv242420".to_string(),
            mode: Mode::Automatic,
        }
    }

    fn execute(&self, sac: &dyn SystemAccess) -> CheckerResult {
        ensure_kubelet_client_ca_configured(sac)
    }
}

// =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<=
pub struct STIGV242424Checker {}
impl Checker for STIGV242424Checker {
    fn metadata(&self) -> CheckerMetadata {
        CheckerMetadata {
            title: "Kubernetes Kubelet must enable tlsPrivateKeyFile for client authentication to secure service.".to_string(),
            id: "V-242424".to_string(),
            level: 2,
            name: "k8sstigv242424".to_string(),
            mode: Mode::Automatic,
        }
    }

    fn execute(&self, sac: &dyn SystemAccess) -> CheckerResult {
        ensure_kubelet_private_key_set(sac)
    }
}

// =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<=
pub struct STIGV242425Checker {}
impl Checker for STIGV242425Checker {
    fn metadata(&self) -> CheckerMetadata {
        CheckerMetadata {
            title: "Kubernetes Kubelet must enable tlsCertFile for client authentication to secure service.".to_string(),
            id: "V-242425".to_string(),
            level: 2,
            name: "k8sstigv242425".to_string(),
            mode: Mode::Automatic,
        }
    }

    fn execute(&self, sac: &dyn SystemAccess) -> CheckerResult {
        ensure_kubelet_private_cert_set(sac)
    }
}

// =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<=
pub struct STIGV242434Checker {}
impl Checker for STIGV242434Checker {
    fn metadata(&self) -> CheckerMetadata {
        CheckerMetadata {
            title: "Kubernetes Kubelet must enable kernel protection.".to_string(),
            id: "V-242434".to_string(),
            level: 1,
            name: "k8sstigv242434".to_string(),
            mode: Mode::Automatic,
        }
    }

    fn execute(&self, sac: &dyn SystemAccess) -> CheckerResult {
        #[derive(Deserialize)]
        struct KubeletConfig {
            #[serde(rename = "protectKernelDefaults")]
            protect_kernel_default: bool,
        }

        let mut result = CheckerResult::default();

        if let Ok(kubelet_file) = sac.open(KUBELET_CONF_FILE) {
            if let Ok(config) = serde_yaml::from_reader::<_, KubeletConfig>(kubelet_file) {
                if !config.protect_kernel_default {
                    result.error = "protectKernelDefault must be set".to_string();
                    result.status = CheckStatus::FAIL;
                } else {
                    result.status = CheckStatus::PASS;
                }
            } else {
                // The default for protectKernelDefaults is false, so we must fail if its not set
                result.error = "protectKernelDefault must be set".to_string();
                result.status = CheckStatus::FAIL;
            }
        } else {
            result.error = format!("unable to read '{KUBELET_CONF_FILE}'");
        }

        result
    }
}

// =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<=
pub struct STIGV242447Checker {}
impl Checker for STIGV242447Checker {
    fn metadata(&self) -> CheckerMetadata {
        CheckerMetadata {
            title: "The Kubernetes Kube Proxy kubeconfig must have file permissions set to 644 or more restrictive.".to_string(),
            id: "V-242447".to_string(),
            level: 2,
            name: "k8sstigv242447".to_string(),
            mode: Mode::Automatic,
        }
    }

    fn execute(&self, sac: &dyn SystemAccess) -> CheckerResult {
        let no_x_xw_xw = S_IXUSR | S_IXGRP | S_IWGRP | S_IXOTH | S_IWOTH;
        check_file_not_mode(sac, KUBEPROXY_KUBECONFIG_FILE, no_x_xw_xw)
    }
}

// =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<=
pub struct STIGV242448Checker {}
impl Checker for STIGV242448Checker {
    fn metadata(&self) -> CheckerMetadata {
        CheckerMetadata {
            title: "The Kubernetes Kube Proxy kubeconfig must be owned by root.".to_string(),
            id: "V-242448".to_string(),
            level: 2,
            name: "k8sstigv242448".to_string(),
            mode: Mode::Automatic,
        }
    }

    fn execute(&self, sac: &dyn SystemAccess) -> CheckerResult {
        ensure_file_owner_and_group_root(sac, KUBEPROXY_KUBECONFIG_FILE)
    }
}

// =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<=
pub struct STIGV242449Checker {}
impl Checker for STIGV242449Checker {
    fn metadata(&self) -> CheckerMetadata {
        CheckerMetadata {
            title: "The Kubernetes Kubelet certificate authority file must have file permissions set to 644 or more restrictive.".to_string(),
            id: "V-242449".to_string(),
            level: 2,
            name: "k8sstigv242449".to_string(),
            mode: Mode::Automatic,
        }
    }

    fn execute(&self, sac: &dyn SystemAccess) -> CheckerResult {
        let no_x_xw_xw = S_IXUSR | S_IXGRP | S_IWGRP | S_IXOTH | S_IWOTH;
        check_file_not_mode(sac, KUBELET_CLIENT_CA_FILE, no_x_xw_xw)
    }
}

// =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<=
pub struct STIGV242450Checker {}
impl Checker for STIGV242450Checker {
    fn metadata(&self) -> CheckerMetadata {
        CheckerMetadata {
            title: "The Kubernetes Kubelet certificate authority must be owned by root."
                .to_string(),
            id: "V-242450".to_string(),
            level: 2,
            name: "k8sstigv242450".to_string(),
            mode: Mode::Automatic,
        }
    }

    fn execute(&self, sac: &dyn SystemAccess) -> CheckerResult {
        ensure_file_owner_and_group_root(sac, KUBELET_CLIENT_CA_FILE)
    }
}

// =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<=
pub struct STIGV242451Checker {}
impl Checker for STIGV242451Checker {
    fn metadata(&self) -> CheckerMetadata {
        CheckerMetadata {
            title: "The Kubernetes component PKI must be owned by root.".to_string(),
            id: "V-242451".to_string(),
            level: 2,
            name: "k8sstigv242451".to_string(),
            mode: Mode::Automatic,
        }
    }

    fn execute(&self, sac: &dyn SystemAccess) -> CheckerResult {
        let mut result = CheckerResult {
            status: CheckStatus::PASS,
            ..Default::default()
        };

        for entry in sac.walk_dir(KUBELET_PKI_DIR) {
            if entry.metadata.uid != 0 || entry.metadata.gid != 0 {
                result.error = format!(
                    "file {:?} has non-root ownership ({}:{})",
                    entry.path, entry.metadata.uid, entry.metadata.gid
                );
                result.status = CheckStatus::FAIL;
                break;
            }
        }
        result
    }
}

// =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<=
pub struct STIGV242466Checker {}
impl Checker for STIGV242466Checker {
    fn metadata(&self) -> CheckerMetadata {
        CheckerMetadata {
            title:
                "The Kubernetes PKI CRT must have file permissions set to 644 or more restrictive."
                    .to_string(),
            id: "V-242466".to_string(),
            level: 2,
            name: "k8sstigv242466".to_string(),
            mode: Mode::Automatic,
        }
    }

    fn execute(&self, sac: &dyn SystemAccess) -> CheckerResult {
        let mut result = CheckerResult {
            status: CheckStatus::PASS,
            ..Default::default()
        };

        for entry in sac.walk_dir(KUBELET_PKI_DIR) {
            if entry.metadata.is_dir() || entry.path.extension().unwrap_or_default() != "crt" {
                continue;
            }
            let no_x_xw_xw = S_IXUSR | S_IXGRP | S_IWGRP | S_IXOTH | S_IWOTH;
            if entry.metadata.mode & no_x_xw_xw as u32 > 0 {
                result.error = format!(
                    "file {:?} must be set to 644 or more restrictive",
                    entry.path,
                );
                result.status = CheckStatus::FAIL;
                break;
            }
        }
        result
    }
}

// =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<=
pub struct STIGV242467Checker {}
impl Checker for STIGV242467Checker {
    fn metadata(&self) -> CheckerMetadata {
        CheckerMetadata {
            title:
                "The Kubernetes PKI keys must have file permissions set to 600 or more restrictive."
                    .to_string(),
            id: "V-242467".to_string(),
            level: 2,
            name: "k8sstigv242467".to_string(),
            mode: Mode::Automatic,
        }
    }

    fn execute(&self, sac: &dyn SystemAccess) -> CheckerResult {
        let mut result = CheckerResult {
            status: CheckStatus::PASS,
            ..Default::default()
        };

        for entry in sac.walk_dir(KUBELET_PKI_DIR) {
            if entry.metadata.is_dir() || entry.path.extension().unwrap_or_default() != "key" {
                continue;
            }
            let no_x_xwr_xwr = S_IXUSR | S_IRWXG | S_IRWXO;
            if entry.metadata.mode & no_x_xwr_xwr as u32 > 0 {
                result.error = format!(
                    "file {:?} must be set to 600 or more restrictive",
                    entry.path,
                );
                result.status = CheckStatus::FAIL;
                break;
            }
        }
        result
    }
}

// =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<=
pub struct STIGV242452Checker {}
impl Checker for STIGV242452Checker {
    fn metadata(&self) -> CheckerMetadata {
        CheckerMetadata {
            title:
            "The Kubernetes kubelet KubeConfig must have file permissions set to 644 or more restrictive."
                .to_string(),
            id: "V-242452".to_string(),
            level: 2,
            name: "k8sstigv242452".to_string(),
            mode: Mode::Automatic,
        }
    }

    fn execute(&self, sac: &dyn SystemAccess) -> CheckerResult {
        let no_x_xw_xw = S_IXUSR | S_IXGRP | S_IWGRP | S_IXOTH | S_IWOTH;
        check_file_not_mode(sac, KUBELET_KUBECONFIG_FILE, no_x_xw_xw)
    }
}
// =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<=
pub struct STIGV242453Checker {}
impl Checker for STIGV242453Checker {
    fn metadata(&self) -> CheckerMetadata {
        CheckerMetadata {
            title: "The Kubernetes kubelet KubeConfig file must be owned by root.".to_string(),
            id: "V-242453".to_string(),
            level: 2,
            name: "k8sstigv242453".to_string(),
            mode: Mode::Automatic,
        }
    }

    fn execute(&self, sac: &dyn SystemAccess) -> CheckerResult {
        ensure_file_owner_and_group_root(sac, KUBELET_KUBECONFIG_FILE)
    }
}

// =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<=
pub struct STIGV242456Checker {}
impl Checker for STIGV242456Checker {
    fn metadata(&self) -> CheckerMetadata {
        CheckerMetadata {
            title:
            "The Kubernetes kubelet config must have file permissions set to 644 or more restrictive."
                .to_string(),
            id: "V-242456".to_string(),
            level: 2,
            name: "k8sstigv242456".to_string(),
            mode: Mode::Automatic,
        }
    }

    fn execute(&self, sac: &dyn SystemAccess) -> CheckerResult {
        let no_x_xw_xw = S_IXUSR | S_IXGRP | S_IWGRP | S_IXOTH | S_IWOTH;
        check_file_not_mode(sac, KUBELET_CONF_FILE, no_x_xw_xw)
    }
}

// =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<=
pub struct STIGV242457Checker {}
impl Checker for STIGV242457Checker {
    fn metadata(&self) -> CheckerMetadata {
        CheckerMetadata {
            title: "The Kubernetes kubelet config must be owned by root.".to_string(),
            id: "V-242457".to_string(),
            level: 2,
            name: "k8sstigv242457".to_string(),
            mode: Mode::Automatic,
        }
    }

    fn execute(&self, sac: &dyn SystemAccess) -> CheckerResult {
        ensure_file_owner_and_group_root(sac, KUBELET_CONF_FILE)
    }
}

// =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<=
pub struct STIGV245541Checker {}
impl Checker for STIGV245541Checker {
    fn metadata(&self) -> CheckerMetadata {
        CheckerMetadata {
            title: "Kubernetes Kubelet must not disable timeouts.".to_string(),
            id: "V-245541".to_string(),
            level: 2,
            name: "k8sstigv245541".to_string(),
            mode: Mode::Automatic,
        }
    }

    fn execute(&self, sac: &dyn SystemAccess) -> CheckerResult {
        #[derive(Deserialize)]
        struct KubeletConfig {
            #[serde(rename = "streamingConnectionIdleTimeout")]
            streaming_connection_idle_timeout: String,
        }

        let mut result = CheckerResult::default();

        if let Ok(kubelet_file) = sac.open(KUBELET_CONF_FILE) {
            if let Ok(config) = serde_yaml::from_reader::<_, KubeletConfig>(kubelet_file) {
                match parse_duration::parse(&config.streaming_connection_idle_timeout) {
                    Ok(value) => {
                        if value.lt(&Duration::from_secs(300)) {
                            result.error = format!(
                                "Kubelet streamingConnectionIdleTimeout is set to {}",
                                config.streaming_connection_idle_timeout
                            );
                            result.status = CheckStatus::FAIL;
                        } else {
                            result.status = CheckStatus::PASS;
                        }
                    }
                    Err(_) => {
                        // unable to parse the duration, so skip the test
                        result.status = CheckStatus::SKIP;
                    }
                }
            } else {
                // This value is normally not present and defaults to 4 hours which passes the check
                result.status = CheckStatus::PASS;
            }
        } else {
            result.error = format!("unable to read '{KUBELET_CONF_FILE}'");
        }

        result
    }
}

// =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<=
pub struct STIGV242398Checker {}
impl Checker for STIGV242398Checker {
    fn metadata(&self) -> CheckerMetadata {
        CheckerMetadata {
            title: "Kubernetes DynamicAuditing must not be enabled.".to_string(),
            id: "V-242398".to_string(),
            level: 2,
            name: "k8sstigv242398".to_string(),
            mode: Mode::Automatic,
        }
    }

    fn execute(&self, _: &dyn SystemAccess) -> CheckerResult {
        // DynamicAuditing feature gate was removed in Kubernetes 1.19 and
        // Bottlerocket only supports newer Kubernetes versions
        // https://kubernetes.io/docs/reference/command-line-tools-reference/feature-gates-removed/
        CheckerResult {
            status: CheckStatus::PASS,
            ..Default::default()
        }
    }
}

// =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<=
pub struct STIGV254801Checker {}
impl Checker for STIGV254801Checker {
    fn metadata(&self) -> CheckerMetadata {
        CheckerMetadata {
            title: "Kubernetes must enable PodSecurity admission controller on static pods and Kubelets."
                .to_string(),
            id: "V-254801".to_string(),
            level: 1,
            name: "k8sstigv254801".to_string(),
            mode: Mode::Automatic,
        }
    }

    fn execute(&self, _: &dyn SystemAccess) -> CheckerResult {
        // PodSecurity feature gate became GA in Kubernetes 1.25 and was removed in 1.28
        // Bottlerocket only supports newer Kubernetes versions
        // https://kubernetes.io/docs/reference/command-line-tools-reference/feature-gates-removed/
        CheckerResult {
            status: CheckStatus::PASS,
            ..Default::default()
        }
    }
}

// =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<=
pub struct STIGV242408Checker {}
impl Checker for STIGV242408Checker {
    fn metadata(&self) -> CheckerMetadata {
        CheckerMetadata {
            title: "The Kubernetes manifest files must have least privileged permissions."
                .to_string(),
            id: "V-242408".to_string(),
            level: 2,
            name: "k8sstigv242408".to_string(),
            mode: Mode::Automatic,
        }
    }

    fn execute(&self, sac: &dyn SystemAccess) -> CheckerResult {
        let mut result = CheckerResult {
            status: CheckStatus::PASS,
            ..Default::default()
        };

        for entry in sac.walk_dir(KUBERNETES_MANIFESTS_DIR) {
            if !entry.metadata.is_file() {
                continue;
            }
            let no_x_xw_xw = S_IXUSR | S_IXGRP | S_IWGRP | S_IXOTH | S_IWOTH;
            if (entry.metadata.mode & no_x_xw_xw as u32) > 0 {
                result.error = format!("file {:?} has invalid permissions", entry.path);
                result.status = CheckStatus::FAIL;
                break;
            }
        }
        result
    }
}

// =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<= =>o.o<=
pub struct STIGV242444Checker {}
impl Checker for STIGV242444Checker {
    fn metadata(&self) -> CheckerMetadata {
        CheckerMetadata {
            title: "The Kubernetes manifest files must be owned by root.".to_string(),
            id: "V-242444".to_string(),
            level: 2,
            name: "k8sstigv242444".to_string(),
            mode: Mode::Automatic,
        }
    }

    fn execute(&self, sac: &dyn SystemAccess) -> CheckerResult {
        let mut result = CheckerResult {
            status: CheckStatus::PASS,
            ..Default::default()
        };

        for entry in sac.walk_dir(KUBERNETES_MANIFESTS_DIR) {
            if entry.metadata.uid != 0 || entry.metadata.gid != 0 {
                result.error = format!(
                    "file {:?} has non-root ownership ({}:{})",
                    entry.path, entry.metadata.uid, entry.metadata.gid
                );
                result.status = CheckStatus::FAIL;
                break;
            }
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bloodhound::results::{CheckStatus, Checker};
    use bloodhound::system_access::UnitTestSystemAccess;

    use std::os::unix::process::ExitStatusExt;
    use std::process::{ExitStatus, Output};

    // STIGV242387Checker tests - readOnlyPort disabled
    #[test]
    pub fn test_k8sstigv242387checker_pass() {
        let mut sac = UnitTestSystemAccess::default();
        let config = r#"
readOnlyPort: 0
"#;
        sac.register_file(KUBELET_CONF_FILE, config);
        let checker = STIGV242387Checker {};
        let result = checker.execute(&sac);
        assert_eq!(result.status, CheckStatus::PASS);
    }

    #[test]
    pub fn test_k8sstigv242387checker_fail_port_not_zero() {
        let mut sac = UnitTestSystemAccess::default();
        let config = r#"
readOnlyPort: 10255
"#;
        sac.register_file(KUBELET_CONF_FILE, config);
        let checker = STIGV242387Checker {};
        let result = checker.execute(&sac);
        assert_eq!(result.status, CheckStatus::FAIL);
    }

    #[test]
    pub fn test_k8sstigv242387checker_file_missing() {
        let sac = UnitTestSystemAccess::default();
        let checker = STIGV242387Checker {};
        let result = checker.execute(&sac);
        assert_eq!(result.status, CheckStatus::SKIP);
    }

    #[test]
    pub fn test_k8sstigv242387checker_invalid_config() {
        let mut sac = UnitTestSystemAccess::default();
        sac.register_file(KUBELET_CONF_FILE, "invalid yaml");
        let checker = STIGV242387Checker {};
        let result = checker.execute(&sac);
        assert_eq!(result.status, CheckStatus::SKIP);
    }

    // STIGV242391Checker tests - anonymous authentication disabled
    #[test]
    pub fn test_k8sstigv242391checker_pass() {
        let mut sac = UnitTestSystemAccess::default();
        let config = r#"
authentication:
  anonymous:
    enabled: false
"#;
        sac.register_file(KUBELET_CONF_FILE, config);
        let checker = STIGV242391Checker {};
        let result = checker.execute(&sac);
        assert_eq!(result.status, CheckStatus::PASS);
    }

    #[test]
    pub fn test_k8sstigv242391checker_fail_anonymous_enabled() {
        let mut sac = UnitTestSystemAccess::default();
        let config = r#"
authentication:
  anonymous:
    enabled: true
"#;
        sac.register_file(KUBELET_CONF_FILE, config);
        let checker = STIGV242391Checker {};
        let result = checker.execute(&sac);
        assert_eq!(result.status, CheckStatus::FAIL);
    }

    #[test]
    pub fn test_k8sstigv242391checker_file_missing() {
        let sac = UnitTestSystemAccess::default();
        let checker = STIGV242391Checker {};
        let result = checker.execute(&sac);
        assert_eq!(result.status, CheckStatus::SKIP);
    }

    #[test]
    pub fn test_k8sstigv242391checker_invalid_config() {
        let mut sac = UnitTestSystemAccess::default();
        sac.register_file(KUBELET_CONF_FILE, "invalid yaml content");
        let checker = STIGV242391Checker {};
        let result = checker.execute(&sac);
        assert_eq!(result.status, CheckStatus::SKIP);
    }

    // STIGV242392Checker tests - explicit authorization (Webhook mode)
    #[test]
    pub fn test_k8sstigv242392checker_pass() {
        let mut sac = UnitTestSystemAccess::default();
        let config = r#"
authorization:
  mode: Webhook
"#;
        sac.register_file(KUBELET_CONF_FILE, config);
        let checker = STIGV242392Checker {};
        let result = checker.execute(&sac);
        assert_eq!(result.status, CheckStatus::PASS);
    }

    #[test]
    pub fn test_k8sstigv242392checker_fail_always_allow() {
        let mut sac = UnitTestSystemAccess::default();
        let config = r#"
authorization:
  mode: AlwaysAllow
"#;
        sac.register_file(KUBELET_CONF_FILE, config);
        let checker = STIGV242392Checker {};
        let result = checker.execute(&sac);
        assert_eq!(result.status, CheckStatus::FAIL);
    }

    #[test]
    pub fn test_k8sstigv242392checker_fail_node_mode() {
        let mut sac = UnitTestSystemAccess::default();
        let config = r#"
authorization:
  mode: Node
"#;
        sac.register_file(KUBELET_CONF_FILE, config);
        let checker = STIGV242392Checker {};
        let result = checker.execute(&sac);
        assert_eq!(result.status, CheckStatus::FAIL);
    }

    #[test]
    pub fn test_k8sstigv242392checker_file_missing() {
        let sac = UnitTestSystemAccess::default();
        let checker = STIGV242392Checker {};
        let result = checker.execute(&sac);
        assert_eq!(result.status, CheckStatus::SKIP);
    }

    // STIGV242393Checker tests - sshd service not running
    #[test]
    pub fn test_k8sstigv242393checker_pass() {
        let mut sac = UnitTestSystemAccess::default();
        sac.register_command(
            SYSTEMCTL_CMD,
            &["show", "--property", "ActiveState", "sshd"],
            Output {
                status: ExitStatus::default(),
                stdout: "ActiveState=inactive".into(),
                stderr: vec![],
            },
        );

        let checker = STIGV242393Checker {};
        let result = checker.execute(&sac);
        assert_eq!(result.status, CheckStatus::PASS);
    }

    #[test]
    pub fn test_k8sstigv242393checker_fail_service_active() {
        let mut sac = UnitTestSystemAccess::default();
        sac.register_command(
            SYSTEMCTL_CMD,
            &["show", "--property", "ActiveState", "sshd"],
            Output {
                status: ExitStatus::default(),
                stdout: "ActiveState=active".into(),
                stderr: vec![],
            },
        );
        let checker = STIGV242393Checker {};
        let result = checker.execute(&sac);
        assert_eq!(result.status, CheckStatus::FAIL);
    }

    #[test]
    pub fn test_k8sstigv242393checker_command_error() {
        let mut sac = UnitTestSystemAccess::default();
        sac.register_command(
            SYSTEMCTL_CMD,
            &["show", "--property", "ActiveState", "sshd"],
            Output {
                status: ExitStatus::from_raw(1),
                stdout: vec![],
                stderr: vec![],
            },
        );

        let checker = STIGV242393Checker {};
        let result = checker.execute(&sac);
        assert_eq!(result.status, CheckStatus::SKIP);
    }


    // STIGV242397Checker tests - staticPodPath disabled
    #[test]
    pub fn test_k8sstigv242397checker_pass_empty_path() {
        let mut sac = UnitTestSystemAccess::default();
        let config = r#"
staticPodPath: ""
"#;
        sac.register_file(KUBELET_CONF_FILE, config);
        let checker = STIGV242397Checker {};
        let result = checker.execute(&sac);
        assert_eq!(result.status, CheckStatus::PASS);
    }

    #[test]
    pub fn test_k8sstigv242397checker_pass_not_configured() {
        let mut sac = UnitTestSystemAccess::default();
        let config = r#"
someOtherSetting: value
"#;
        sac.register_file(KUBELET_CONF_FILE, config);
        let checker = STIGV242397Checker {};
        let result = checker.execute(&sac);
        assert_eq!(result.status, CheckStatus::PASS);
    }

    #[test]
    pub fn test_k8sstigv242397checker_fail_path_set() {
        let mut sac = UnitTestSystemAccess::default();
        let config = r#"
staticPodPath: "/etc/kubernetes/manifests"
"#;
        sac.register_file(KUBELET_CONF_FILE, config);
        let checker = STIGV242397Checker {};
        let result = checker.execute(&sac);
        assert_eq!(result.status, CheckStatus::FAIL);
    }

    #[test]
    pub fn test_k8sstigv242397checker_file_missing() {
        let sac = UnitTestSystemAccess::default();
        let checker = STIGV242397Checker {};
        let result = checker.execute(&sac);
        assert_eq!(result.status, CheckStatus::SKIP);
    }

    // STIGV242406Checker tests - KubeletConfiguration file ownership
    #[test]
    pub fn test_k8sstigv242406checker_pass() {
        let mut sac = UnitTestSystemAccess::default();
        // Register files in the kubelet config directory with root ownership
        sac.register_file_with_metadata(
            &format!("{KUBELET_CONFIG_DIR}/config"),
            "config content",
            libc::S_IFREG | 0o644,
            0,
            0,
        );
        sac.register_file_with_metadata(
            &format!("{KUBELET_CONFIG_DIR}/kubeconfig"),
            "kubeconfig content",
            libc::S_IFREG | 0o644,
            0,
            0,
        );
        let checker = STIGV242406Checker {};
        let result = checker.execute(&sac);
        assert_eq!(result.status, CheckStatus::PASS);
    }

    #[test]
    pub fn test_k8sstigv242406checker_fail_wrong_owner() {
        let mut sac = UnitTestSystemAccess::default();
        sac.register_file_with_metadata(
            &format!("{KUBELET_CONFIG_DIR}/config"),
            "",
            libc::S_IFREG | 0o644,
            1000,
            0,
        );
        let checker = STIGV242406Checker {};
        let result = checker.execute(&sac);
        assert_eq!(result.status, CheckStatus::FAIL);
    }

    #[test]
    pub fn test_k8sstigv242406checker_fail_wrong_group() {
        let mut sac = UnitTestSystemAccess::default();
        sac.register_file_with_metadata(
            &format!("{KUBELET_CONFIG_DIR}/config"),
            "",
            libc::S_IFREG | 0o644,
            0,
            1000,
        );
        let checker = STIGV242406Checker {};
        let result = checker.execute(&sac);
        assert_eq!(result.status, CheckStatus::FAIL);
    }

    // STIGV242407Checker tests - KubeletConfiguration file permissions
    #[test]
    pub fn test_k8sstigv242407checker_pass() {
        let mut sac = UnitTestSystemAccess::default();
        // Register files with proper permissions (644)
        sac.register_file_with_metadata(
            &format!("{KUBELET_CONFIG_DIR}/config"),
            "config content",
            libc::S_IFREG | 0o644,
            0,
            0,
        );
        sac.register_file_with_metadata(
            &format!("{KUBELET_CONFIG_DIR}/kubeconfig"),
            "kubeconfig content",
            libc::S_IFREG | 0o600,
            0,
            0,
        );
        let checker = STIGV242407Checker {};
        let result = checker.execute(&sac);
        assert_eq!(result.status, CheckStatus::PASS);
    }

    #[test]
    pub fn test_k8sstigv242407checker_fail_executable() {
        let mut sac = UnitTestSystemAccess::default();
        sac.register_file_with_metadata(
            &format!("{KUBELET_CONFIG_DIR}/config"),
            "",
            libc::S_IFREG | 0o755,
            0,
            0,
        );
        let checker = STIGV242407Checker {};
        let result = checker.execute(&sac);
        assert_eq!(result.status, CheckStatus::FAIL);
    }

    #[test]
    pub fn test_k8sstigv242407checker_fail_group_write() {
        let mut sac = UnitTestSystemAccess::default();
        sac.register_file_with_metadata(
            &format!("{KUBELET_CONFIG_DIR}/config"),
            "",
            libc::S_IFREG | 0o664,
            0,
            0,
        );
        let checker = STIGV242407Checker {};
        let result = checker.execute(&sac);
        assert_eq!(result.status, CheckStatus::FAIL);
    }

    #[test]
    pub fn test_k8sstigv242407checker_skips_directories() {
        let mut sac = UnitTestSystemAccess::default();
        // Directory with bad permissions should be skipped
        sac.register_file_with_metadata(
            &format!("{KUBELET_CONFIG_DIR}/subdir"),
            "",
            libc::S_IFDIR | 0o777,
            0,
            0,
        );
        let checker = STIGV242407Checker {};
        let result = checker.execute(&sac);
        assert_eq!(result.status, CheckStatus::PASS);
    }

    // STIGV242420Checker tests - SSL Certificate Authority set
    #[test]
    pub fn test_k8sstigv242420checker_pass() {
        let mut sac = UnitTestSystemAccess::default();
        let config = r#"
authentication:
  x509:
    clientCAFile: /etc/kubernetes/pki/ca.crt
"#;
        sac.register_file(KUBELET_CONF_FILE, config);
        // Register the CA file to simulate it exists
        sac.register_file("/etc/kubernetes/pki/ca.crt", "dummy ca content");
        let checker = STIGV242420Checker {};
        let result = checker.execute(&sac);
        assert_eq!(result.status, CheckStatus::PASS);
    }

    #[test]
    pub fn test_k8sstigv242420checker_fail_ca_file_missing() {
        let mut sac = UnitTestSystemAccess::default();
        let config = r#"
authentication:
  x509:
    clientCAFile: /nonexistent/ca.crt
"#;
        sac.register_file(KUBELET_CONF_FILE, config);
        let checker = STIGV242420Checker {};
        let result = checker.execute(&sac);
        assert_eq!(result.status, CheckStatus::FAIL);
    }

    #[test]
    pub fn test_k8sstigv242420checker_fail_empty_ca_file() {
        let mut sac = UnitTestSystemAccess::default();
        let config = r#"
authentication:
  x509:
    clientCAFile: ""
"#;
        sac.register_file(KUBELET_CONF_FILE, config);
        let checker = STIGV242420Checker {};
        let result = checker.execute(&sac);
        assert_eq!(result.status, CheckStatus::FAIL);
    }

    #[test]
    pub fn test_k8sstigv242420checker_file_missing() {
        let sac = UnitTestSystemAccess::default();
        let checker = STIGV242420Checker {};
        let result = checker.execute(&sac);
        assert_eq!(result.status, CheckStatus::SKIP);
    }

    // STIGV242424Checker tests - tlsPrivateKeyFile enabled
    #[test]
    pub fn test_k8sstigv242424checker_pass_with_key_file() {
        let mut sac = UnitTestSystemAccess::default();
        let config = r#"
tlsPrivateKeyFile: /etc/kubernetes/pki/kubelet.key
"#;
        sac.register_file(KUBELET_CONF_FILE, config);
        sac.register_file("/etc/kubernetes/pki/kubelet.key", "dummy key");
        let checker = STIGV242424Checker {};
        let result = checker.execute(&sac);
        assert_eq!(result.status, CheckStatus::PASS);
    }

    #[test]
    pub fn test_k8sstigv242424checker_pass_without_key_file() {
        let mut sac = UnitTestSystemAccess::default();
        let config = r#"
someOtherSetting: value
"#;
        sac.register_file(KUBELET_CONF_FILE, config);
        let checker = STIGV242424Checker {};
        let result = checker.execute(&sac);
        assert_eq!(result.status, CheckStatus::PASS);
    }

    #[test]
    pub fn test_k8sstigv242424checker_fail_key_missing() {
        let mut sac = UnitTestSystemAccess::default();
        let config = r#"
tlsPrivateKeyFile: /nonexistent/kubelet.key
"#;
        sac.register_file(KUBELET_CONF_FILE, config);
        let checker = STIGV242424Checker {};
        let result = checker.execute(&sac);
        assert_eq!(result.status, CheckStatus::FAIL);
    }

    #[test]
    pub fn test_k8sstigv242424checker_fail_empty_key_path() {
        let mut sac = UnitTestSystemAccess::default();
        let config = r#"
tlsPrivateKeyFile: ""
"#;
        sac.register_file(KUBELET_CONF_FILE, config);
        let checker = STIGV242424Checker {};
        let result = checker.execute(&sac);
        assert_eq!(result.status, CheckStatus::FAIL);
    }

    #[test]
    pub fn test_k8sstigv242424checker_file_missing() {
        let sac = UnitTestSystemAccess::default();
        let checker = STIGV242424Checker {};
        let result = checker.execute(&sac);
        assert_eq!(result.status, CheckStatus::SKIP);
    }

    // STIGV242425Checker tests - tlsCertFile enabled
    #[test]
    pub fn test_k8sstigv242425checker_pass_with_cert_file() {
        let mut sac = UnitTestSystemAccess::default();
        let config = r#"
tlsCertFile: /etc/kubernetes/pki/kubelet.crt
"#;
        sac.register_file(KUBELET_CONF_FILE, config);
        sac.register_file("/etc/kubernetes/pki/kubelet.crt", "dummy cert");
        let checker = STIGV242425Checker {};
        let result = checker.execute(&sac);
        assert_eq!(result.status, CheckStatus::PASS);
    }

    #[test]
    pub fn test_k8sstigv242425checker_pass_without_cert_file() {
        let mut sac = UnitTestSystemAccess::default();
        let config = r#"
someOtherSetting: value
"#;
        sac.register_file(KUBELET_CONF_FILE, config);
        let checker = STIGV242425Checker {};
        let result = checker.execute(&sac);
        assert_eq!(result.status, CheckStatus::PASS);
    }

    #[test]
    pub fn test_k8sstigv242425checker_fail_cert_missing() {
        let mut sac = UnitTestSystemAccess::default();
        let config = r#"
tlsCertFile: /nonexistent/kubelet.crt
"#;
        sac.register_file(KUBELET_CONF_FILE, config);
        let checker = STIGV242425Checker {};
        let result = checker.execute(&sac);
        assert_eq!(result.status, CheckStatus::FAIL);
    }

    #[test]
    pub fn test_k8sstigv242425checker_fail_empty_cert_path() {
        let mut sac = UnitTestSystemAccess::default();
        let config = r#"
tlsCertFile: ""
"#;
        sac.register_file(KUBELET_CONF_FILE, config);
        let checker = STIGV242425Checker {};
        let result = checker.execute(&sac);
        assert_eq!(result.status, CheckStatus::FAIL);
    }

    // STIGV242434Checker tests - kernel protection enabled
    #[test]
    pub fn test_k8sstigv242434checker_pass() {
        let mut sac = UnitTestSystemAccess::default();
        let config = r#"
protectKernelDefaults: true
"#;
        sac.register_file(KUBELET_CONF_FILE, config);
        let checker = STIGV242434Checker {};
        let result = checker.execute(&sac);
        assert_eq!(result.status, CheckStatus::PASS);
    }

    #[test]
    pub fn test_k8sstigv242434checker_fail_disabled() {
        let mut sac = UnitTestSystemAccess::default();
        let config = r#"
protectKernelDefaults: false
"#;
        sac.register_file(KUBELET_CONF_FILE, config);
        let checker = STIGV242434Checker {};
        let result = checker.execute(&sac);
        assert_eq!(result.status, CheckStatus::FAIL);
    }

    #[test]
    pub fn test_k8sstigv242434checker_fail_not_configured() {
        let mut sac = UnitTestSystemAccess::default();
        let config = r#"
someOtherSetting: value
"#;
        sac.register_file(KUBELET_CONF_FILE, config);
        let checker = STIGV242434Checker {};
        let result = checker.execute(&sac);
        assert_eq!(result.status, CheckStatus::FAIL);
    }

    #[test]
    pub fn test_k8sstigv242434checker_file_missing() {
        let sac = UnitTestSystemAccess::default();
        let checker = STIGV242434Checker {};
        let result = checker.execute(&sac);
        assert_eq!(result.status, CheckStatus::SKIP);
    }

    // STIGV242447Checker tests - Kube Proxy kubeconfig file permissions
    #[test]
    pub fn test_k8sstigv242447checker_pass() {
        let mut sac = UnitTestSystemAccess::default();
        sac.register_file_with_metadata(KUBEPROXY_KUBECONFIG_FILE, "", 0o644, 0, 0);
        let checker = STIGV242447Checker {};
        let result = checker.execute(&sac);
        assert_eq!(result.status, CheckStatus::PASS);
    }

    #[test]
    pub fn test_k8sstigv242447checker_pass_more_restrictive() {
        let mut sac = UnitTestSystemAccess::default();
        sac.register_file_with_metadata(KUBEPROXY_KUBECONFIG_FILE, "", 0o600, 0, 0);
        let checker = STIGV242447Checker {};
        let result = checker.execute(&sac);
        assert_eq!(result.status, CheckStatus::PASS);
    }

    #[test]
    pub fn test_k8sstigv242447checker_fail_too_permissive() {
        let mut sac = UnitTestSystemAccess::default();
        sac.register_file_with_metadata(KUBEPROXY_KUBECONFIG_FILE, "", 0o666, 0, 0);
        let checker = STIGV242447Checker {};
        let result = checker.execute(&sac);
        assert_eq!(result.status, CheckStatus::FAIL);
    }

    #[test]
    pub fn test_k8sstigv242447checker_fail_executable() {
        let mut sac = UnitTestSystemAccess::default();
        sac.register_file_with_metadata(KUBEPROXY_KUBECONFIG_FILE, "", 0o755, 0, 0);
        let checker = STIGV242447Checker {};
        let result = checker.execute(&sac);
        assert_eq!(result.status, CheckStatus::FAIL);
    }

    #[test]
    pub fn test_k8sstigv242447checker_file_missing() {
        let sac = UnitTestSystemAccess::default();
        let checker = STIGV242447Checker {};
        let result = checker.execute(&sac);
        assert_eq!(result.status, CheckStatus::SKIP);
    }

    // STIGV242448Checker tests - Kube Proxy kubeconfig file ownership
    #[test]
    pub fn test_k8sstigv242448checker_pass() {
        let mut sac = UnitTestSystemAccess::default();
        sac.register_file_with_metadata(KUBEPROXY_KUBECONFIG_FILE, "", 0o644, 0, 0);
        let checker = STIGV242448Checker {};
        let result = checker.execute(&sac);
        assert_eq!(result.status, CheckStatus::PASS);
    }

    #[test]
    pub fn test_k8sstigv242448checker_fail_wrong_owner() {
        let mut sac = UnitTestSystemAccess::default();
        sac.register_file_with_metadata(KUBEPROXY_KUBECONFIG_FILE, "", 0o644, 1000, 0);
        let checker = STIGV242448Checker {};
        let result = checker.execute(&sac);
        assert_eq!(result.status, CheckStatus::FAIL);
    }

    #[test]
    pub fn test_k8sstigv242448checker_fail_wrong_group() {
        let mut sac = UnitTestSystemAccess::default();
        sac.register_file_with_metadata(KUBEPROXY_KUBECONFIG_FILE, "", 0o644, 0, 100);
        let checker = STIGV242448Checker {};
        let result = checker.execute(&sac);
        assert_eq!(result.status, CheckStatus::FAIL);
    }

    // STIGV242449Checker tests - Kubelet certificate authority file permissions
    #[test]
    pub fn test_k8sstigv242449checker_pass() {
        let mut sac = UnitTestSystemAccess::default();
        sac.register_file_with_metadata(KUBELET_CLIENT_CA_FILE, "", 0o644, 0, 0);
        let checker = STIGV242449Checker {};
        let result = checker.execute(&sac);
        assert_eq!(result.status, CheckStatus::PASS);
    }

    #[test]
    pub fn test_k8sstigv242449checker_pass_more_restrictive() {
        let mut sac = UnitTestSystemAccess::default();
        sac.register_file_with_metadata(KUBELET_CLIENT_CA_FILE, "", 0o600, 0, 0);
        let checker = STIGV242449Checker {};
        let result = checker.execute(&sac);
        assert_eq!(result.status, CheckStatus::PASS);
    }

    #[test]
    pub fn test_k8sstigv242449checker_fail_too_permissive() {
        let mut sac = UnitTestSystemAccess::default();
        sac.register_file_with_metadata(KUBELET_CLIENT_CA_FILE, "", 0o666, 0, 0);
        let checker = STIGV242449Checker {};
        let result = checker.execute(&sac);
        assert_eq!(result.status, CheckStatus::FAIL);
    }

    #[test]
    pub fn test_k8sstigv242449checker_fail_executable() {
        let mut sac = UnitTestSystemAccess::default();
        sac.register_file_with_metadata(KUBELET_CLIENT_CA_FILE, "", 0o755, 0, 0);
        let checker = STIGV242449Checker {};
        let result = checker.execute(&sac);
        assert_eq!(result.status, CheckStatus::FAIL);
    }

    #[test]
    pub fn test_k8sstigv242449checker_file_missing() {
        let sac = UnitTestSystemAccess::default();
        let checker = STIGV242449Checker {};
        let result = checker.execute(&sac);
        assert_eq!(result.status, CheckStatus::SKIP);
    }

    // STIGV242450Checker tests - Kubelet certificate authority ownership
    #[test]
    pub fn test_k8sstigv242450checker_pass() {
        let mut sac = UnitTestSystemAccess::default();
        sac.register_file_with_metadata(KUBELET_CLIENT_CA_FILE, "", 0o644, 0, 0);
        let checker = STIGV242450Checker {};
        let result = checker.execute(&sac);
        assert_eq!(result.status, CheckStatus::PASS);
    }

    #[test]
    pub fn test_k8sstigv242450checker_fail_wrong_owner() {
        let mut sac = UnitTestSystemAccess::default();
        sac.register_file_with_metadata(KUBELET_CLIENT_CA_FILE, "", 0o644, 1000, 0);
        let checker = STIGV242450Checker {};
        let result = checker.execute(&sac);
        assert_eq!(result.status, CheckStatus::FAIL);
    }

    #[test]
    pub fn test_k8sstigv242450checker_fail_wrong_group() {
        let mut sac = UnitTestSystemAccess::default();
        sac.register_file_with_metadata(KUBELET_CLIENT_CA_FILE, "", 0o644, 0, 100);
        let checker = STIGV242450Checker {};
        let result = checker.execute(&sac);
        assert_eq!(result.status, CheckStatus::FAIL);
    }

    // STIGV242451Checker tests - Kubernetes component PKI ownership
    #[test]
    pub fn test_k8sstigv242451checker_pass() {
        let mut sac = UnitTestSystemAccess::default();
        // Register PKI files with root ownership
        sac.register_file_with_metadata(
            &format!("{KUBELET_PKI_DIR}/kubelet.crt"),
            "cert content",
            libc::S_IFREG | 0o644,
            0,
            0,
        );
        sac.register_file_with_metadata(
            &format!("{KUBELET_PKI_DIR}/kubelet.key"),
            "key content",
            libc::S_IFREG | 0o600,
            0,
            0,
        );
        let checker = STIGV242451Checker {};
        let result = checker.execute(&sac);
        assert_eq!(result.status, CheckStatus::PASS);
    }

    #[test]
    pub fn test_k8sstigv242451checker_fail_wrong_owner() {
        let mut sac = UnitTestSystemAccess::default();
        sac.register_file_with_metadata(
            &format!("{KUBELET_PKI_DIR}/kubelet.crt"),
            "",
            libc::S_IFREG | 0o644,
            1000,
            0,
        );
        let checker = STIGV242451Checker {};
        let result = checker.execute(&sac);
        assert_eq!(result.status, CheckStatus::FAIL);
    }

    #[test]
    pub fn test_k8sstigv242451checker_fail_wrong_group() {
        let mut sac = UnitTestSystemAccess::default();
        sac.register_file_with_metadata(
            &format!("{KUBELET_PKI_DIR}/kubelet.key"),
            "",
            libc::S_IFREG | 0o600,
            0,
            1000,
        );
        let checker = STIGV242451Checker {};
        let result = checker.execute(&sac);
        assert_eq!(result.status, CheckStatus::FAIL);
    }

    // STIGV242466Checker tests - PKI CRT file permissions
    #[test]
    pub fn test_k8sstigv242466checker_pass() {
        let mut sac = UnitTestSystemAccess::default();
        sac.register_file_with_metadata(
            &format!("{KUBELET_PKI_DIR}/kubelet.crt"),
            "",
            libc::S_IFREG | 0o644,
            0,
            0,
        );
        let checker = STIGV242466Checker {};
        let result = checker.execute(&sac);
        assert_eq!(result.status, CheckStatus::PASS);
    }

    #[test]
    pub fn test_k8sstigv242466checker_fail_executable() {
        let mut sac = UnitTestSystemAccess::default();
        sac.register_file_with_metadata(
            &format!("{KUBELET_PKI_DIR}/kubelet.crt"),
            "",
            libc::S_IFREG | 0o755,
            0,
            0,
        );
        let checker = STIGV242466Checker {};
        let result = checker.execute(&sac);
        assert_eq!(result.status, CheckStatus::FAIL);
    }

    #[test]
    pub fn test_k8sstigv242466checker_skips_non_crt() {
        let mut sac = UnitTestSystemAccess::default();
        // .key file with bad permissions should be skipped
        sac.register_file_with_metadata(
            &format!("{KUBELET_PKI_DIR}/kubelet.key"),
            "",
            libc::S_IFREG | 0o777,
            0,
            0,
        );
        let checker = STIGV242466Checker {};
        let result = checker.execute(&sac);
        assert_eq!(result.status, CheckStatus::PASS);
    }

    // STIGV242467Checker tests - PKI key file permissions
    #[test]
    pub fn test_k8sstigv242467checker_pass() {
        let mut sac = UnitTestSystemAccess::default();
        sac.register_file_with_metadata(
            &format!("{KUBELET_PKI_DIR}/kubelet.key"),
            "",
            libc::S_IFREG | 0o600,
            0,
            0,
        );
        let checker = STIGV242467Checker {};
        let result = checker.execute(&sac);
        assert_eq!(result.status, CheckStatus::PASS);
    }

    #[test]
    pub fn test_k8sstigv242467checker_fail_group_readable() {
        let mut sac = UnitTestSystemAccess::default();
        sac.register_file_with_metadata(
            &format!("{KUBELET_PKI_DIR}/kubelet.key"),
            "",
            libc::S_IFREG | 0o640,
            0,
            0,
        );
        let checker = STIGV242467Checker {};
        let result = checker.execute(&sac);
        assert_eq!(result.status, CheckStatus::FAIL);
    }

    #[test]
    pub fn test_k8sstigv242467checker_skips_non_key() {
        let mut sac = UnitTestSystemAccess::default();
        // .crt file with bad permissions should be skipped
        sac.register_file_with_metadata(
            &format!("{KUBELET_PKI_DIR}/kubelet.crt"),
            "",
            libc::S_IFREG | 0o777,
            0,
            0,
        );
        let checker = STIGV242467Checker {};
        let result = checker.execute(&sac);
        assert_eq!(result.status, CheckStatus::PASS);
    }

    // STIGV242408Checker tests - Kubernetes manifest file permissions
    #[test]
    pub fn test_k8sstigv242408checker_pass() {
        let mut sac = UnitTestSystemAccess::default();
        sac.register_file_with_metadata(
            &format!("{KUBERNETES_MANIFESTS_DIR}/pod.yaml"),
            "",
            libc::S_IFREG | 0o644,
            0,
            0,
        );
        let checker = STIGV242408Checker {};
        let result = checker.execute(&sac);
        assert_eq!(result.status, CheckStatus::PASS);
    }

    #[test]
    pub fn test_k8sstigv242408checker_fail_executable() {
        let mut sac = UnitTestSystemAccess::default();
        sac.register_file_with_metadata(
            &format!("{KUBERNETES_MANIFESTS_DIR}/pod.yaml"),
            "",
            libc::S_IFREG | 0o755,
            0,
            0,
        );
        let checker = STIGV242408Checker {};
        let result = checker.execute(&sac);
        assert_eq!(result.status, CheckStatus::FAIL);
    }

    #[test]
    pub fn test_k8sstigv242408checker_skips_directories() {
        let mut sac = UnitTestSystemAccess::default();
        sac.register_file_with_metadata(
            &format!("{KUBERNETES_MANIFESTS_DIR}/subdir"),
            "",
            libc::S_IFDIR | 0o777,
            0,
            0,
        );
        let checker = STIGV242408Checker {};
        let result = checker.execute(&sac);
        assert_eq!(result.status, CheckStatus::PASS);
    }

    // STIGV242444Checker tests - Kubernetes manifest file ownership
    #[test]
    pub fn test_k8sstigv242444checker_pass() {
        let mut sac = UnitTestSystemAccess::default();
        sac.register_file_with_metadata(
            &format!("{KUBERNETES_MANIFESTS_DIR}/pod.yaml"),
            "",
            libc::S_IFREG | 0o644,
            0,
            0,
        );
        let checker = STIGV242444Checker {};
        let result = checker.execute(&sac);
        assert_eq!(result.status, CheckStatus::PASS);
    }

    #[test]
    pub fn test_k8sstigv242444checker_fail_wrong_owner() {
        let mut sac = UnitTestSystemAccess::default();
        sac.register_file_with_metadata(
            &format!("{KUBERNETES_MANIFESTS_DIR}/pod.yaml"),
            "",
            libc::S_IFREG | 0o644,
            1000,
            0,
        );
        let checker = STIGV242444Checker {};
        let result = checker.execute(&sac);
        assert_eq!(result.status, CheckStatus::FAIL);
    }

    #[test]
    pub fn test_k8sstigv242444checker_fail_wrong_group() {
        let mut sac = UnitTestSystemAccess::default();
        sac.register_file_with_metadata(
            &format!("{KUBERNETES_MANIFESTS_DIR}/pod.yaml"),
            "",
            libc::S_IFREG | 0o644,
            0,
            1000,
        );
        let checker = STIGV242444Checker {};
        let result = checker.execute(&sac);
        assert_eq!(result.status, CheckStatus::FAIL);
    }

    // STIGV242452Checker tests - kubelet KubeConfig file permissions
    #[test]
    pub fn test_k8sstigv242452checker_pass() {
        let mut sac = UnitTestSystemAccess::default();
        sac.register_file_with_metadata(KUBELET_KUBECONFIG_FILE, "", 0o644, 0, 0);
        let checker = STIGV242452Checker {};
        let result = checker.execute(&sac);
        assert_eq!(result.status, CheckStatus::PASS);
    }

    #[test]
    pub fn test_k8sstigv242452checker_pass_more_restrictive() {
        let mut sac = UnitTestSystemAccess::default();
        sac.register_file_with_metadata(KUBELET_KUBECONFIG_FILE, "", 0o600, 0, 0);
        let checker = STIGV242452Checker {};
        let result = checker.execute(&sac);
        assert_eq!(result.status, CheckStatus::PASS);
    }

    #[test]
    pub fn test_k8sstigv242452checker_fail_too_permissive() {
        let mut sac = UnitTestSystemAccess::default();
        sac.register_file_with_metadata(KUBELET_KUBECONFIG_FILE, "", 0o666, 0, 0);
        let checker = STIGV242452Checker {};
        let result = checker.execute(&sac);
        assert_eq!(result.status, CheckStatus::FAIL);
    }

    #[test]
    pub fn test_k8sstigv242452checker_fail_executable() {
        let mut sac = UnitTestSystemAccess::default();
        sac.register_file_with_metadata(KUBELET_KUBECONFIG_FILE, "", 0o755, 0, 0);
        let checker = STIGV242452Checker {};
        let result = checker.execute(&sac);
        assert_eq!(result.status, CheckStatus::FAIL);
    }

    #[test]
    pub fn test_k8sstigv242452checker_file_missing() {
        let sac = UnitTestSystemAccess::default();
        let checker = STIGV242452Checker {};
        let result = checker.execute(&sac);
        assert_eq!(result.status, CheckStatus::SKIP);
    }

    // STIGV242453Checker tests - kubelet KubeConfig file ownership
    #[test]
    pub fn test_k8sstigv242453checker_pass() {
        let mut sac = UnitTestSystemAccess::default();
        sac.register_file_with_metadata(KUBELET_KUBECONFIG_FILE, "", 0o644, 0, 0);
        let checker = STIGV242453Checker {};
        let result = checker.execute(&sac);
        assert_eq!(result.status, CheckStatus::PASS);
    }

    #[test]
    pub fn test_k8sstigv242453checker_fail_wrong_owner() {
        let mut sac = UnitTestSystemAccess::default();
        sac.register_file_with_metadata(KUBELET_KUBECONFIG_FILE, "", 0o644, 1000, 0);
        let checker = STIGV242453Checker {};
        let result = checker.execute(&sac);
        assert_eq!(result.status, CheckStatus::FAIL);
    }

    #[test]
    pub fn test_k8sstigv242453checker_fail_wrong_group() {
        let mut sac = UnitTestSystemAccess::default();
        sac.register_file_with_metadata(KUBELET_KUBECONFIG_FILE, "", 0o644, 0, 100);
        let checker = STIGV242453Checker {};
        let result = checker.execute(&sac);
        assert_eq!(result.status, CheckStatus::FAIL);
    }

    #[test]
    pub fn test_k8sstigv242453checker_file_missing() {
        let sac = UnitTestSystemAccess::default();
        let checker = STIGV242453Checker {};
        let result = checker.execute(&sac);
        assert_eq!(result.status, CheckStatus::SKIP);
    }

    // STIGV242456Checker tests - kubelet config file permissions
    #[test]
    pub fn test_k8sstigv242456checker_pass() {
        let mut sac = UnitTestSystemAccess::default();
        sac.register_file_with_metadata(KUBELET_CONF_FILE, "", 0o644, 0, 0);
        let checker = STIGV242456Checker {};
        let result = checker.execute(&sac);
        assert_eq!(result.status, CheckStatus::PASS);
    }

    #[test]
    pub fn test_k8sstigv242456checker_pass_more_restrictive() {
        let mut sac = UnitTestSystemAccess::default();
        sac.register_file_with_metadata(KUBELET_CONF_FILE, "", 0o600, 0, 0);
        let checker = STIGV242456Checker {};
        let result = checker.execute(&sac);
        assert_eq!(result.status, CheckStatus::PASS);
    }

    #[test]
    pub fn test_k8sstigv242456checker_fail_too_permissive() {
        let mut sac = UnitTestSystemAccess::default();
        sac.register_file_with_metadata(KUBELET_CONF_FILE, "", 0o666, 0, 0);
        let checker = STIGV242456Checker {};
        let result = checker.execute(&sac);
        assert_eq!(result.status, CheckStatus::FAIL);
    }

    #[test]
    pub fn test_k8sstigv242456checker_fail_executable() {
        let mut sac = UnitTestSystemAccess::default();
        sac.register_file_with_metadata(KUBELET_CONF_FILE, "", 0o755, 0, 0);
        let checker = STIGV242456Checker {};
        let result = checker.execute(&sac);
        assert_eq!(result.status, CheckStatus::FAIL);
    }

    #[test]
    pub fn test_k8sstigv242456checker_file_missing() {
        let sac = UnitTestSystemAccess::default();
        let checker = STIGV242456Checker {};
        let result = checker.execute(&sac);
        assert_eq!(result.status, CheckStatus::SKIP);
    }

    // STIGV242457Checker tests - kubelet config file ownership
    #[test]
    pub fn test_k8sstigv242457checker_pass() {
        let mut sac = UnitTestSystemAccess::default();
        sac.register_file_with_metadata(KUBELET_CONF_FILE, "", 0o644, 0, 0);
        let checker = STIGV242457Checker {};
        let result = checker.execute(&sac);
        assert_eq!(result.status, CheckStatus::PASS);
    }

    #[test]
    pub fn test_k8sstigv242457checker_fail_wrong_owner() {
        let mut sac = UnitTestSystemAccess::default();
        sac.register_file_with_metadata(KUBELET_CONF_FILE, "", 0o644, 1000, 0);
        let checker = STIGV242457Checker {};
        let result = checker.execute(&sac);
        assert_eq!(result.status, CheckStatus::FAIL);
    }

    #[test]
    pub fn test_k8sstigv242457checker_fail_wrong_group() {
        let mut sac = UnitTestSystemAccess::default();
        sac.register_file_with_metadata(KUBELET_CONF_FILE, "", 0o644, 0, 100);
        let checker = STIGV242457Checker {};
        let result = checker.execute(&sac);
        assert_eq!(result.status, CheckStatus::FAIL);
    }

    // STIGV245541Checker tests - Kubelet timeouts not disabled
    #[test]
    pub fn test_k8sstigv245541checker_pass_valid_timeout() {
        let mut sac = UnitTestSystemAccess::default();
        let config = r#"
streamingConnectionIdleTimeout: "5m"
"#;
        sac.register_file(KUBELET_CONF_FILE, config);
        let checker = STIGV245541Checker {};
        let result = checker.execute(&sac);
        assert_eq!(result.status, CheckStatus::PASS);
    }

    #[test]
    pub fn test_k8sstigv245541checker_pass_long_timeout() {
        let mut sac = UnitTestSystemAccess::default();
        let config = r#"
streamingConnectionIdleTimeout: "1h"
"#;
        sac.register_file(KUBELET_CONF_FILE, config);
        let checker = STIGV245541Checker {};
        let result = checker.execute(&sac);
        assert_eq!(result.status, CheckStatus::PASS);
    }

    #[test]
    pub fn test_k8sstigv245541checker_pass_not_configured() {
        let mut sac = UnitTestSystemAccess::default();
        let config = r#"
someOtherSetting: value
"#;
        sac.register_file(KUBELET_CONF_FILE, config);
        let checker = STIGV245541Checker {};
        let result = checker.execute(&sac);
        assert_eq!(result.status, CheckStatus::PASS);
    }

    #[test]
    pub fn test_k8sstigv245541checker_fail_short_timeout() {
        let mut sac = UnitTestSystemAccess::default();
        let config = r#"
streamingConnectionIdleTimeout: "30s"
"#;
        sac.register_file(KUBELET_CONF_FILE, config);
        let checker = STIGV245541Checker {};
        let result = checker.execute(&sac);
        assert_eq!(result.status, CheckStatus::FAIL);
    }

    #[test]
    pub fn test_k8sstigv245541checker_fail_zero_timeout() {
        let mut sac = UnitTestSystemAccess::default();
        let config = r#"
streamingConnectionIdleTimeout: "0"
"#;
        sac.register_file(KUBELET_CONF_FILE, config);
        let checker = STIGV245541Checker {};
        let result = checker.execute(&sac);
        assert_eq!(result.status, CheckStatus::FAIL);
    }

    #[test]
    pub fn test_k8sstigv245541checker_skip_invalid_duration() {
        let mut sac = UnitTestSystemAccess::default();
        let config = r#"
streamingConnectionIdleTimeout: "invalid-duration"
"#;
        sac.register_file(KUBELET_CONF_FILE, config);
        let checker = STIGV245541Checker {};
        let result = checker.execute(&sac);
        assert_eq!(result.status, CheckStatus::SKIP);
    }

    #[test]
    pub fn test_k8sstigv245541checker_file_missing() {
        let sac = UnitTestSystemAccess::default();
        let checker = STIGV245541Checker {};
        let result = checker.execute(&sac);
        assert_eq!(result.status, CheckStatus::SKIP);
    }

    #[test]
    pub fn test_k8sstigv245541checker_invalid_config() {
        let mut sac = UnitTestSystemAccess::default();
        sac.register_file(KUBELET_CONF_FILE, "invalid yaml");
        let checker = STIGV245541Checker {};
        let result = checker.execute(&sac);
        assert_eq!(result.status, CheckStatus::PASS);
    }
}
