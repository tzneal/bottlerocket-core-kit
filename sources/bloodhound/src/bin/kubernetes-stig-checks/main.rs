mod checks;

use bloodhound::results::*;
use bloodhound::system_access::NativeSystemAccess;
use checks::*;
use std::env;
use std::path::Path;

fn main() {
    let args: Vec<String> = env::args().collect();
    let cmd_name = Path::new(&args[0])
        .file_name()
        .unwrap_or_default()
        .to_str()
        .unwrap_or_default();

    let checker: Box<dyn Checker> = match cmd_name {
        "k8sstigv242387" => Box::new(STIGV242387Checker {}),
        "k8sstigv242391" => Box::new(STIGV242391Checker {}),
        "k8sstigv242392" => Box::new(STIGV242392Checker {}),
        "k8sstigv242393" => Box::new(STIGV242393Checker {}),
        "k8sstigv242394" => Box::new(ManualChecker{
            title: "Kubernetes Worker Nodes must not have the sshd service enabled. (sshd not installed in Bottlerocket)".to_string(),
            id: "V-242394".to_string(),
            level: 2,
            name: "k8sstigv242394".to_string(),
        }),
        "k8sstigv242397" => Box::new(STIGV242397Checker {}),
        "k8sstigv242398" => Box::new(STIGV242398Checker {}),
        "k8sstigv242399" => Box::new(STIGV242399Checker{}), 
        "k8sstigv242404" => Box::new(ManualChecker {
            name: cmd_name.to_string(),
            title: "Kubernetes Kubelet must deny hostname override. (not valid for Bottlerocket)"
                .to_string(),
            id: "V-242404".to_string(),
            level: 2,
        }),
        "k8sstigv242406" => Box::new(STIGV242406Checker {}),
        "k8sstigv242407" => Box::new(STIGV242407Checker {}),
        "k8sstigv242408" => Box::new(STIGV242408Checker {}),
        "k8sstigv242420" => Box::new(STIGV242420Checker {}),
        "k8sstigv242424" => Box::new(STIGV242424Checker {}),
        "k8sstigv242425" => Box::new(STIGV242425Checker {}),
        "k8sstigv242434" => Box::new(STIGV242434Checker {}),
        "k8sstigv242442" => Box::new(ManualChecker {
            name: cmd_name.to_string(),
            title: "Kubernetes must remove old components after updated versions have been installed. (not valid for Bottlerocket)"
                .to_string(),
            id: "V-242442".to_string(),
            level: 2,
        }),
        "k8sstigv242443" => Box::new(ManualChecker {
            name: cmd_name.to_string(),
            title: "Kubernetes must contain the latest updates as authorized by IAVMs, CTOs, DTMs, and STIGs."
                .to_string(),
            id: "V-242443".to_string(),
            level: 2,
        }),
        "k8sstigv242444" => Box::new(STIGV242444Checker {}),
        "k8sstigv242447" => Box::new(STIGV242447Checker {}),
        "k8sstigv242448" => Box::new(STIGV242448Checker {}),
        "k8sstigv242449" => Box::new(STIGV242449Checker {}),
        "k8sstigv242450" => Box::new(STIGV242450Checker {}),
        "k8sstigv242451" => Box::new(STIGV242451Checker {}),
        "k8sstigv242466" => Box::new(STIGV242466Checker {}),
        "k8sstigv242467" => Box::new(STIGV242467Checker {}),
        "k8sstigv242452" => Box::new(STIGV242452Checker {}),
        "k8sstigv242453" => Box::new(STIGV242453Checker {}),
        "k8sstigv242456" => Box::new(STIGV242456Checker {}),
        "k8sstigv242457" => Box::new(STIGV242457Checker {}),
        "k8sstigv245541" => Box::new(STIGV245541Checker {}),
        "k8sstigv242396" => Box::new(ManualChecker {
            name: cmd_name.to_string(),
            title: "Kubernetes kubectl cp command must give expected access and results. (kubectl not installed on Bottlerocket worker nodes)"
                .to_string(),
            id: "V-242396".to_string(),
            level: 2,
        }),
        "k8sstigv254801" => Box::new(STIGV254801Checker {}),
        &_ => {
            eprintln!("Command {cmd_name} is not supported.");
            return;
        }
    };

    // Check if the metadata subcommand is being called
    let get_metadata = env::args().nth(1).unwrap_or_default() == "metadata";

    let sac = NativeSystemAccess {};
    if get_metadata {
        let metadata = checker.metadata();
        println!("{metadata}");
    } else {
        let result = checker.execute(&sac);
        println!("{result}");
    }
}
