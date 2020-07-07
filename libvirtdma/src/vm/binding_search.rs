#![allow(dead_code)]
use crate::vm::VMBinding;
use memmem::Searcher;
use regex::bytes::Regex;

pub fn str_chunks<'a>(s: &'a str, n: usize) -> Box<dyn Iterator<Item = &'a str> + 'a> {
    Box::new(
        s.as_bytes()
            .chunks(n)
            .map(|c| std::str::from_utf8(c).unwrap()),
    )
}

impl VMBinding {
    pub fn memmem(haystack: &[u8], needle: &[u8]) -> Option<usize> {
        memmem::TwoWaySearcher::new(needle).search_in(haystack)
    }

    pub fn pmemmem(haystack: &[u8], needle_string: &str) -> Result<Vec<usize>, String> {
        let mut restr = String::from("(?-u:");
        for ch in str_chunks(&needle_string, 2) {
            let chunk: Vec<char> = ch.chars().collect();
            if chunk.len() != 2 {
                return Err("input needle_string without even length".to_string());
            }
            let (first, second) = (*chunk.get(0).unwrap(), *chunk.get(1).unwrap());
            let qm_present = first == '?' || second == '?';
            let wildcard = first == '?' && second == '?';
            if qm_present && !wildcard {
                return Err("needle_string has wildcards of uneven length".to_string());
            }
            if wildcard {
                restr += ".";
            } else {
                restr += "\\x";
                restr += ch;
            }
        }
        restr += ")";

        let re: Regex = match Regex::new(&restr) {
            Ok(r) => r,
            Err(e) => return Err(e.to_string()),
        };
        Ok(re.find_iter(haystack).map(|f| f.start()).collect())
    }

    pub fn memmemn(haystack: &[u8], needle: &[u8], max_opt: Option<usize>) -> Vec<usize> {
        match Self::memmem(haystack, needle) {
            None => vec![],
            Some(offset) => {
                let res = vec![offset];
                match max_opt {
                    Some(1) => res,
                    other => {
                        let updatedn = match other {
                            Some(x) => Some(x - 1),
                            None => None,
                        };
                        let needle_end = offset + needle.len();
                        let mut downstream_results =
                            Self::memmemn(&haystack[needle_end..], needle, updatedn);
                        for res in downstream_results.iter_mut() {
                            *res += needle_end;
                        }
                        let mut res = vec![offset];
                        res.append(&mut downstream_results);
                        res
                    }
                }
            }
        }
    }
}
