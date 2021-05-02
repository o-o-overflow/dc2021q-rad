extern crate nyx_space as nyx;

use chrono::{Datelike, Timelike, Utc};
use nyx::celestia::{Cosm, Epoch, State};
use rad_common::compute_radiation;

fn main() {
    let ts = Utc::now();
    let dt = Epoch::from_gregorian_utc(
        ts.year(),
        ts.month() as _,
        ts.day() as _,
        ts.hour() as _,
        ts.minute() as _,
        ts.second() as _,
        ts.nanosecond(),
    );
    let cosm = Cosm::from_xb("data/de438s");
    let eme2k = cosm.frame("EME2000");

    let mut low = vec![];
    let mut med = vec![];
    let mut high = vec![];

    for x in -30..30 {
        for y in -30..30 {
            let state = State::from_position((x * 1000) as _, (y * 1000) as _, 0.0, dt, eme2k);
            let level = compute_radiation(state.geodetic_latitude(), state.geodetic_height());
            // println!("({}, {}) {}", x, y, level);
            if level > 350.0 {
                high.push((x as f64, y as f64));
            } else if level > 100.0 {
                med.push((x as f64, y as f64));
            } else if level > 10.0 {
                low.push((x as f64, y as f64));
            }
        }
    }

    println!("L {:?}", low);
    println!("M {:?}", med);
    println!("H {:?}", high);
}
