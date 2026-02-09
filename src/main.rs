use thirtyfour::prelude::*;
use serde::Deserialize;
use serde_json::Value;
use std::collections::HashSet;
use std::env;
use std::time::Duration;

#[derive(Deserialize)]
struct Packet {
    #[serde(alias = "Title", alias = "FJTitle")]
    t: Option<String>,
    #[serde(alias = "DatePublished", alias = "PublishedDate", alias = "Date")]
    d: Option<String>,
    #[serde(alias = "NewsID", alias = "Id")]
    i: Option<String>,
    #[serde(alias = "Body", alias = "Description")]
    desc: Option<String>,
    #[serde(alias = "Breaking")]
    br: Option<bool>,
    #[serde(alias = "Actual")]
    act: Option<String>,
    #[serde(alias = "Forecast")]
    fc: Option<String>,
    #[serde(alias = "Previous")]
    pr: Option<String>,
}

const KERNEL_MOD: &str = r#"
window.ws_spy_active = true;
window.ws_captured_logs = [];
const nativeWebSocket = window.WebSocket;
window.WebSocket = function(...args) {
  const socket = new nativeWebSocket(...args);
  socket.addEventListener('message', function(event) {
    if(window.ws_captured_logs) {
        window.ws_captured_logs.push(event.data);
    }
  });
  return socket;
};
"#;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let k_key = env::var("K_KEY").expect("E1");
    let ref_id = env::var("REF_ID").expect("E2");
    let c_client = env::var("C_CLIENT").expect("E3");
    let c_secret = env::var("C_SECRET").expect("E4");
    let t_target = env::var("T_TARGET").expect("E5");

    let mut buf = HashSet::new();

    let mut caps = DesiredCapabilities::chrome();
    caps.add_chrome_arg("--headless")?;
    caps.add_chrome_arg("--no-sandbox")?;
    caps.add_chrome_arg("--disable-dev-shm-usage")?;
    caps.add_chrome_arg("--window-size=1920,1080")?; // FIX: سایز بزرگ برای جلوگیری از تداخل
    caps.add_chrome_arg("--disable-blink-features=AutomationControlled")?;
    caps.add_chrome_arg("user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")?;

    let driver = WebDriver::new("http://localhost:4444", caps).await?;

    driver.goto(&t_target).await?;
    tokio::time::sleep(Duration::from_secs(8)).await;

    // FIX: Cookie Killer - تلاش برای بستن بنرهای مزاحم
    let _ = driver.execute_script(r#"
        try {
            const keywords = ["accept", "agree", "allow", "consent", "got it", "continue"];
            const btns = document.querySelectorAll("button, a, div[role='button']");
            for (let btn of btns) {
                if (btn.innerText && keywords.some(k => btn.innerText.toLowerCase().includes(k))) {
                    btn.click();
                }
            }
        } catch(e) {}
    "#, Vec::new()).await;
    tokio::time::sleep(Duration::from_secs(2)).await;

    // کلیک روی دکمه Sign In اصلی
    let _ = driver.execute_script(r#"
        let btn = document.querySelector("a[href*='SignIn']") || document.querySelector(".login");
        if(btn) btn.click();
    "#, Vec::new()).await;
    tokio::time::sleep(Duration::from_secs(4)).await;

    // پر کردن فیلد ایمیل
    let f1 = driver.find(By::Css("#ctl00_SignInSignUp_loginForm1_inputEmail")).await?;
    f1.clear().await?;
    f1.send_keys(&c_client).await?;

    // پر کردن فیلد پسورد
    let f2 = driver.find(By::Css("#ctl00_SignInSignUp_loginForm1_inputPassword")).await?;
    f2.clear().await?;
    f2.send_keys(&c_secret).await?;

    // FIX: کلیک اجباری (Force Click) روی دکمه ورود با جاوااسکریپت
    // این روش حتی اگر بنر روی دکمه باشد هم کار می‌کند
    let _ = driver.execute_script(r#"
        let btn = document.querySelector("#ctl00_SignInSignUp_loginForm1_btnLogin");
        if (btn) btn.click();
    "#, Vec::new()).await?;

    println!("Login submitted via JS force-click");
    tokio::time::sleep(Duration::from_secs(15)).await;

    // تزریق اسکریپت جاسوسی
    driver.execute_script(KERNEL_MOD, Vec::new()).await?;
    driver.execute_script("if($.connection && $.connection.hub){$.connection.hub.stop();setTimeout(()=>$.connection.hub.start(),1000);}", Vec::new()).await?;

    println!("System engaged. Listening...");

    loop {
        let res = driver.execute_script(r#"
            if (typeof window.ws_captured_logs === 'undefined') return [];
            return window.ws_captured_logs.splice(0, window.ws_captured_logs.length);
        "#, Vec::new()).await;

        if let Ok(val) = res {
            if let Ok(logs) = val.convert::<Vec<String>>() {
                for raw in logs {
                    if raw == "{}" || raw.contains(r#"{"S":1,"M":[]}"#) { continue; }
                    
                    if let Ok(v) = serde_json::from_str::<Value>(&raw) {
                        if let Some(m_arr) = v.get("M").and_then(|m| m.as_array()) {
                            for item in m_arr {
                                if let Some(a_arr) = item.get("A").and_then(|a| a.as_array()) {
                                    if let Some(payload) = a_arr.first().and_then(|p| p.as_str()) {
                                        let items: Vec<Packet> = if let Ok(list) = serde_json::from_str(payload) {
                                            list
                                        } else if let Ok(single) = serde_json::from_str(payload) {
                                            vec![single]
                                        } else {
                                            vec![]
                                        };

                                        for p in items {
                                            let tit = p.t.clone().unwrap_or_default();
                                            if tit.is_empty() { continue; }
                                            
                                            let dat = p.d.clone().unwrap_or_default();
                                            let hash_in = format!("{}_{}", tit, dat);
                                            let sig = format!("{:x}", md5::compute(hash_in));

                                            if buf.contains(&sig) { continue; }
                                            buf.insert(sig);

                                            let ico = if p.br.unwrap_or(false) { "🚨" } else { "" };
                                            let mut out = format!("{}<b>{}</b>\n\n", ico, tit);
                                            
                                            if let Some(d) = &p.desc {
                                                out.push_str(d);
                                                out.push_str("\n\n");
                                            }
                                            
                                            out.push_str("<b>INF:</b>\n");
                                            out.push_str(&format!("ID: {}\n", p.i.unwrap_or("-".to_string())));
                                            out.push_str(&format!("TS: {}\n", dat));

                                            if p.act.is_some() || p.fc.is_some() {
                                                out.push_str("\n<b>DT:</b>\n");
                                                out.push_str(&format!("A: {} | F: {} | P: {}\n", 
                                                    p.act.unwrap_or("-".to_string()),
                                                    p.fc.unwrap_or("-".to_string()),
                                                    p.pr.unwrap_or("-".to_string())
                                                ));
                                            }

                                            let client = reqwest::Client::new();
                                            let _ = client.post(format!("https://api.telegram.org/bot{}/sendMessage", k_key))
                                                .form(&[
                                                    ("chat_id", &ref_id),
                                                    ("text", &out),
                                                    ("parse_mode", &"HTML".to_string()),
                                                    ("disable_web_page_preview", &"true".to_string())
                                                ])
                                                .send()
                                                .await;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        tokio::time::sleep(Duration::from_millis(150)).await;
    }
}
