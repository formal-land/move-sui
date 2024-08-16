use move_binary_format::file_format::{
    Bytecode, CodeUnit, FunctionDefinition, FunctionHandle,
    IdentifierIndex, ModuleHandleIndex, SignatureIndex,
    FunctionDefinitionIndex, empty_module
};

use move_core_types::vm_status::StatusCode;
use move_binary_format::CompiledModule;
use move_bytecode_verifier_meter::dummy::DummyMeter;
use crate::absint::FunctionContext;
use crate::type_safety;


fn make_module(code: Vec<Bytecode>) -> CompiledModule {
    let code_unit = CodeUnit {
        code,
        ..Default::default()
    };

    let fun_def = FunctionDefinition {
        code: Some(code_unit.clone()),
        ..Default::default()
    };

    let fun_handle = FunctionHandle {
        module: ModuleHandleIndex(0),
        name: IdentifierIndex(0),
        parameters: SignatureIndex(0),
        return_: SignatureIndex(0),
        type_parameters: vec![],
    };

    let mut module = empty_module();
    module.function_handles.push(fun_handle);
    module.function_defs.push(fun_def);

    module
}

fn get_fun_context(module: &CompiledModule) -> FunctionContext {
    FunctionContext::new(
        &module,
        FunctionDefinitionIndex(0), 
        module.function_defs[0].code.as_ref().unwrap(),
        &module.function_handles[0],
    )
}


#[test]
fn test_br_true_false_correct_type() {
    for instr in vec![
        Bytecode::BrTrue(0),
        Bytecode::BrFalse(0),
    ] {
        let code = vec![Bytecode::LdTrue, instr];
    let module = make_module(code);
    let fun_context = get_fun_context(&module);
    let result = type_safety::verify(&module, &fun_context, &mut DummyMeter);
    assert!(result.is_ok());
}
}

#[test]
fn test_br_true_false_wrong_type() {
    for instr in vec![
        Bytecode::BrTrue(0),
        Bytecode::BrFalse(0),
    ] {
        let code = vec![Bytecode::LdU32(0), instr];
    let module = make_module(code);
    let fun_context = get_fun_context(&module);
    let result = type_safety::verify(&module, &fun_context, &mut DummyMeter);
    assert_eq!(
        result.unwrap_err().major_status(),
        StatusCode::BR_TYPE_MISMATCH_ERROR
    );
    }
}

#[test]
#[should_panic]
fn test_br_true_false_no_arg() {
    for instr in vec![
        Bytecode::BrTrue(0),
        Bytecode::BrFalse(0),
    ] {
        let code = vec![instr];
    let module = make_module(code);
    let fun_context = get_fun_context(&module);
    let _result = type_safety::verify(&module, &fun_context, &mut DummyMeter);
    }
}


#[test]
fn test_abort_correct_type() {
    let code = vec![Bytecode::LdU64(0), Bytecode::Abort];
    let module = make_module(code);
    let fun_context = get_fun_context(&module);
    let result = type_safety::verify(&module, &fun_context, &mut DummyMeter);
    assert!(result.is_ok());
}


#[test]
fn test_abort_wrong_type() {
    let code = vec![Bytecode::LdU32(0), Bytecode::Abort];
    let module = make_module(code);
    let fun_context = get_fun_context(&module);
    let result = type_safety::verify(&module, &fun_context, &mut DummyMeter);
    assert_eq!(
        result.unwrap_err().major_status(),
        StatusCode::ABORT_TYPE_MISMATCH_ERROR
    );
}

#[test]
#[should_panic]
fn test_abort_no_arg() {
    let code = vec![Bytecode::Abort];
    let module = make_module(code);
    let fun_context = get_fun_context(&module);
    let _result = type_safety::verify(&module, &fun_context, &mut DummyMeter);
}
