#[cfg(test)]
mod test {
    use std::path::Path;
    use std::fs;
    use serde::{Deserialize};
    use std::fs::File;
    use std::io::{BufReader, Read, Write};
    use crate::dk_crypto::DkEncrypt;

    #[test]
    fn test_1() {
        let s = DkEncrypt::decrypt_customer_file(r#"C:\Users\denis\wks-tools\doka-export\data\prodCustomer.enc"#);
        println!("s = {:?}", &s);
    }

    #[test]
    fn test_2() {
        let s0 = DkEncrypt::decrypt_file(r#"C:\Users\denis\wks-tools\doka-export\data\x.2445182641ed49c89651d86dd7c468270000000000"#,
                                         "ZMBy1nxeze7dv59OCSeCoDayVijUQD96HyLev3YvhqM");
        let b0 = &s0.unwrap()[..];
        // dbg!(b0.len());
        let mut f = File::create(r#"C:\Users\denis\wks-tools\doka-export\data\toto.pdf"#).expect("💣 WOOOOOOW !!");
        let r0 = f.write_all(b0);

        println!("<<s>> = {:?}", r0);
    }

    #[test]
    fn test_3() {
        //let s0 = DkEncrypt::decrypt_file(r#"C:\Users\denis\wks-tools\doka-export\data\x.2445182641ed49c89651d86dd7c468270000000000"#,
        //                                 "ZMBy1nxeze7dv59OCSeCoDayVijUQD96HyLev3YvhqM" );
        let mut f = File::create(r#"C:\Users\denis\wks-tools\doka-export\data\toto.pdf"#).expect("💣 WOOOOOOW !!");
        let s0 = DkEncrypt::decrypt_file(r#"C:\Users\denis\wks-tools\doka-export\data\x.24b19d42c416413c9f23ba6a20e079980000000000"#,
                                         "ZMBy1nxeze7dv59OCSeCoDayVijUQD96HyLev3YvhqM");
        let b0 = &s0.unwrap()[..];
        let _r0 = f.write_all(b0);
        let s1 = DkEncrypt::decrypt_file(r#"C:\Users\denis\wks-tools\doka-export\data\x.24b19d42c416413c9f23ba6a20e079980000000001"#,
                                         "ZMBy1nxeze7dv59OCSeCoDayVijUQD96HyLev3YvhqM");
        let b1 = &s1.unwrap()[..];
        let r0 = f.write_all(b1);
        println!("<<s>> = {:?}", r0);
    }

    #[test]
    fn export_doka() {
        let target = r#"C:\Users\denis\wks-tools\doka-export\data\denis_pdf\"#;

        let paths = fs::read_dir(r#"C:\Users\denis\wks-tools\doka-export\data\denis_file\"#).unwrap();
        let mut f: Option<File> = None;
        let mut reference_base = String::from("");
        for path in paths {
            println!("Start : {:?}", &path);
            // extract the file number, last 10 chars
            let p = &path.unwrap();
            let name = p.file_name();
            let len = name.len();
            let string_name = name.into_string().unwrap().clone();
            let short = &string_name[len - 10..len];
            let base = &string_name[0..len - 10];

            // dbg!(base, short);

            if reference_base != base {
                // we have a new base !!!
                let target_file = format!("{}{}.pdf", target, base);
                f = Some(File::create(&target_file).expect("💣 WOOOOOOW !!"));
                reference_base = base.to_owned().clone();
            }

            // Write the part
            // dbg!(&string_name);
            let s0 = DkEncrypt::decrypt_file(p.path().to_str().unwrap()
                                             /*&string_name[..]*/, "ZMBy1nxeze7dv59OCSeCoDayVijUQD96HyLev3YvhqM");
            let b0 = &s0.unwrap()[..];
            if let Some(ff) = f.as_mut() {
                // dbg!(&ff);
                let _ = ff.write_all(b0);
            }
            println!("End: {}", p.path().display())
        }
    }


    #[derive(Deserialize)]
    struct Record {
        /*    year: u16,
        make: String,
        model: String,
        description: String,*/

        label: String,
        label_2: String,
        name: String,
        file_identifier: String,
        original_file_size: u64,
        mime_type: String,
    }

    #[test]
    fn organize_doka() {
        let file = File::open(r#"C:\Users\denis\wks-tools\doka-export\data\data.csv"#).expect("Cannot read the customer file");
        let mut buf_reader = BufReader::new(file);
        let mut buf: Vec<u8> = vec![];
        let _n = buf_reader.read_to_end(&mut buf).expect("Didn't read enough");

        // Read the CSV file
        //  let csv = "year,make,model,description
        // 1948,Porsche,356,Luxury sports car
        // 1967,Ford,Mustang fastback 1967,American car";

        let mut reader = csv::Reader::from_reader(/*csv.as_bytes()*/ &buf[..]);
        // Loop over the csv data
        for record in reader.deserialize() {
            let record: Record = record.unwrap();
            println!(
                "{}, {} , {} , {}",
                record.label,
                record.label_2,
                record.name,
                record.file_identifier
            );

            let target = r#"C:\Users\denis\wks-tools\doka-export\data\organized_file\"#;
            let new_folder = format!("{}{}\\{}", target, record.label, record.label_2);
            fs::create_dir_all(Path::new(&new_folder));
            // find the corresponding file

            // move it into the new folder and rename it
            let source = format!("{}{}{}{}", r#"C:\Users\denis\wks-tools\doka-export\data\denis_pdf\"#, "x.", record.file_identifier, ".pdf");
            let cible = format!("{}\\{}", new_folder, record.name);
            // dbg!(&source, &cible);
            fs::rename(&source, &cible);
        }
    }
}