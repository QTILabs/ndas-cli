use dialoguer::{theme::ColorfulTheme, Confirm, Input, Select};
use pnet::datalink;
use std::io::Result as IOResult;
use std::time::Duration;

pub(crate) fn get_interfaces_name() -> Vec<String> {
    datalink::interfaces()
        .iter()
        .map(|nic| nic.name.clone())
        .collect::<Vec<String>>()
}

pub(crate) fn get_interface_selection() -> IOResult<String> {
    let interfaces_name = get_interfaces_name();
    let selection_index = Select::with_theme(&ColorfulTheme::default())
        .with_prompt("Please select network interface:")
        .default(0)
        .items(&interfaces_name[..])
        .interact()?;

    Ok(interfaces_name.get(selection_index).unwrap().clone())
}

pub(crate) fn get_file_clipping() -> IOResult<u64> {
    let clipping_options = &[
        ("1 MiB", 1024 * 1024),
        ("16 MiB", 16 * 1024 * 1024),
        ("64 MiB", 64 * 1024 * 1024),
        ("256 MiB", 256 * 1024 * 1024),
        ("1024 MiB", 1024 * 1024 * 1024),
    ];
    let selection_index = Select::with_theme(&ColorfulTheme::default())
        .with_prompt("Please select max file dump size:")
        .default(0)
        .items(&clipping_options.iter().map(|options| options.0).collect::<Vec<&str>>()[..])
        .interact()?;

    Ok(clipping_options.get(selection_index).unwrap().1)
}

pub(crate) fn get_duration() -> IOResult<Duration> {
    let inputted_duration: u64 = Input::new().with_prompt("Input recording duration (minutes)").interact()?;

    Ok(Duration::from_secs(inputted_duration * 60))
}

pub(crate) fn get_promiscuous_mode() -> IOResult<bool> {
    Confirm::new().with_prompt("Enable promiscuous?").interact()
}
