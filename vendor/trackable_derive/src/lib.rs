//! This crate provides `TrackableError` derive macro.
//!
//! This crate should not be used directly.
//! See [trackable] documentation for the usage of `#[derive(TrackableError)]`.
//!
//! [trackable]: https://docs.rs/trackable
#![recursion_limit = "128"]
extern crate proc_macro;
#[macro_use]
extern crate quote;
#[macro_use]
extern crate syn;

use proc_macro::TokenStream;
use syn::DeriveInput;

#[doc(hidden)]
#[proc_macro_derive(TrackableError, attributes(trackable))]
pub fn derive_trackable_error(input: TokenStream) -> TokenStream {
    let ast = parse_macro_input!(input as DeriveInput);
    let expanded = impl_trackable_error(&ast);
    expanded.into()
}

fn impl_trackable_error(ast: &syn::DeriveInput) -> impl Into<TokenStream> {
    let error = &ast.ident;
    let error_kind = get_error_kind(&ast.attrs);
    quote! {
        impl ::std::ops::Deref for #error {
            type Target = ::trackable::error::TrackableError<#error_kind>;

            #[inline]
            fn deref(&self) -> &Self::Target {
                &self.0
            }
        }
        impl ::std::fmt::Display for #error {
            fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
                self.0.fmt(f)
            }
        }
        impl ::std::error::Error for #error {
            fn source(&self) -> Option<&(::std::error::Error + 'static)> {
                self.0.source()
            }
        }
        impl ::trackable::Trackable for #error {
            type Event = ::trackable::Location;

            #[inline]
            fn history(&self) -> Option<&::trackable::History<Self::Event>> {
                self.0.history()
            }

            #[inline]
            fn history_mut(&mut self) -> Option<&mut ::trackable::History<Self::Event>> {
                self.0.history_mut()
            }
        }
        impl From<::trackable::error::TrackableError<#error_kind>> for #error {
            #[inline]
            fn from(f: ::trackable::error::TrackableError<#error_kind>) -> Self {
                #error(f)
            }
        }
        impl From<#error> for ::trackable::error::TrackableError<#error_kind> {
            #[inline]
            fn from(f: #error) -> Self {
                f.0
            }
        }
        impl From<#error_kind> for #error {
            #[inline]
            fn from(f: #error_kind) -> Self {
                use ::trackable::error::ErrorKindExt;
                f.error().into()
            }
        }
    }
}

fn get_error_kind(attrs: &[syn::Attribute]) -> syn::Path {
    use syn::Lit::*;
    use syn::Meta::*;
    use syn::MetaNameValue;
    use syn::NestedMeta::*;

    let mut error_kind = "ErrorKind".to_owned();

    let attrs = attrs
        .iter()
        .filter_map(|attr| {
            let path = &attr.path;
            if quote!(#path).to_string() == "trackable" {
                Some(
                    attr.interpret_meta()
                        .unwrap_or_else(|| panic!("invalid trackable syntax: {}", quote!(attr))),
                )
            } else {
                None
            }
        })
        .flat_map(|m| match m {
            List(l) => l.nested,
            tokens => panic!("unsupported syntax: {}", quote!(#tokens).to_string()),
        })
        .map(|m| match m {
            Meta(m) => m,
            tokens => panic!("unsupported syntax: {}", quote!(#tokens).to_string()),
        });
    for attr in attrs {
        match &attr {
            NameValue(MetaNameValue {
                ident,
                lit: Str(value),
                ..
            }) if ident == "error_kind" => {
                error_kind = value.value().to_string();
            }
            i @ List(..) | i @ Word(..) | i @ NameValue(..) => {
                panic!("unsupported option: {}", quote!(#i))
            }
        }
    }

    match syn::parse_str(&error_kind) {
        Err(e) => panic!("{:?} is not a valid type (parse error: {})", error_kind, e),
        Ok(path) => path,
    }
}
