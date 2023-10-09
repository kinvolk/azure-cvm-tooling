use anyhow::{anyhow, Result};
use clap::Parser;
use log::{info, warn};
use quick_xml::de::from_str;
use quick_xml::se::to_string;
use serde::{Deserialize, Serialize};
use std::convert::From;
use std::thread;
use std::time::Duration;

const WIRESERVER_ENDPOINT: &str = "http://168.63.129.16/machine";
const RETRY_DELAY: Duration = Duration::from_secs(2);

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// WireServer endpoint (you should not need to change this)
    #[arg(short, long, default_value = WIRESERVER_ENDPOINT)]
    wireserver_endpoint: String,
    /// Number of retries
    #[arg(short, long, default_value = "3")]
    retries: u32,
}

#[derive(Deserialize, Serialize, Debug)]
#[serde(rename_all = "PascalCase")]
struct InnerHealth {
    state: String,
}

#[derive(Deserialize, Serialize, Debug)]
#[serde(rename_all = "PascalCase")]
struct Role {
    instance_id: String,
    health: InnerHealth,
}

#[derive(Deserialize, Serialize, Debug)]
#[serde(rename_all = "PascalCase")]
struct RoleInstance {
    instance_id: String,
}

trait RoleContainer {}
#[derive(Deserialize, Serialize, Debug)]
#[serde(rename_all = "PascalCase")]
struct Container<T: RoleContainer> {
    container_id: String,
    role_instance_list: T,
}

#[derive(Deserialize, Serialize, Debug)]
#[serde(rename_all = "PascalCase")]
struct RoleList {
    role: Vec<Role>,
}
impl RoleContainer for RoleList {}

#[derive(Deserialize, Serialize, Debug)]
#[serde(rename_all = "PascalCase")]
struct RoleInstanceList {
    role_instance: Vec<RoleInstance>,
}
impl RoleContainer for RoleInstanceList {}

#[derive(Deserialize, Serialize, Debug)]
#[serde(rename_all = "PascalCase")]
struct Health {
    goal_state_incarnation: u32,
    container: Container<RoleList>,
}

impl Health {
    fn new(info: &InstanceInfo) -> Self {
        let role = Role {
            instance_id: info.instance_id.clone(),
            health: InnerHealth {
                state: "Ready".into(),
            },
        };
        let role_instance_list = RoleList { role: vec![role] };
        Health {
            goal_state_incarnation: info.incarnation,
            container: Container {
                container_id: info.container_id.clone(),
                role_instance_list,
            },
        }
    }
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
struct GoalState {
    container: Container<RoleInstanceList>,
    incarnation: u32,
}

struct InstanceInfo {
    instance_id: String,
    container_id: String,
    incarnation: u32,
}

impl From<GoalState> for InstanceInfo {
    fn from(gs: GoalState) -> Self {
        let container_id = gs.container.container_id;
        let instance_id = gs.container.role_instance_list.role_instance[0]
            .instance_id
            .clone();
        let incarnation = gs.incarnation;
        InstanceInfo {
            instance_id,
            container_id,
            incarnation,
        }
    }
}

fn get_goalstate(endpoint: &str) -> Result<GoalState> {
    let body = ureq::get(endpoint)
        .query("comp", "goalstate")
        .set("x-ms-version", "2012-11-30")
        .call()?
        .into_string()?;
    let goal_state: GoalState = from_str(&body)?;
    Ok(goal_state)
}

fn post_health(endpoint: &str, health: &Health) -> Result<()> {
    let body = to_string(health)?;
    ureq::post(endpoint)
        .query("comp", "health")
        .set("content-type", "text/xml;charset=utf-8")
        .set("x-ms-version", "2012-11-30")
        .set("x-ms-agent-name", "custom-provisioning")
        .send_string(&body)?;
    Ok(())
}

fn register(wireserver_endpoint: &str) -> Result<()> {
    let goal_state = get_goalstate(wireserver_endpoint)?;
    let info: InstanceInfo = goal_state.into();
    let health = Health::new(&info);
    post_health(wireserver_endpoint, &health)?;
    Ok(())
}

fn main() -> Result<()> {
    let args = Args::parse();
    for _ in 0..args.retries {
        if register(&args.wireserver_endpoint).is_ok() {
            info!("Successfully reported health");
            return Ok(());
        }
        warn!("Failed to report health, retrying...");
        thread::sleep(RETRY_DELAY);
    }

    Err(anyhow!("Failed to report health"))
}

#[test]
fn parse_goalstate() {
    let goal_state_str = r#"
        <?xml version="1.0" encoding="utf-8"?>
        <GoalState>
            <Incarnation>1</Incarnation>
            <Container>
                <ContainerId>123</ContainerId>
                <RoleInstanceList>
                    <RoleInstance>
                        <InstanceId>456</InstanceId>
                    </RoleInstance>
                </RoleInstanceList>
            </Container>
        </GoalState>
    "#;

    let goal_state: GoalState = from_str(goal_state_str).unwrap();
    let info: InstanceInfo = goal_state.into();
    assert_eq!(info.container_id, "123");
    assert_eq!(info.instance_id, "456");
    assert_eq!(info.incarnation, 1);
}
