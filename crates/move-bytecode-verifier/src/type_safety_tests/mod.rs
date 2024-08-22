use move_binary_format::file_format::{
    Bytecode, CodeUnit, FunctionDefinition, FunctionHandle,
    IdentifierIndex, ModuleHandleIndex, SignatureIndex,
    FunctionDefinitionIndex, empty_module
};

use move_core_types::u256::U256;
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


#[test]
fn test_cast_correct_type() {
    for instr in vec![
        Bytecode::CastU8,
        Bytecode::CastU16,
        Bytecode::CastU32,
        Bytecode::CastU64,
        Bytecode::CastU128,
        Bytecode::CastU256,
    ] {
        let code = vec![Bytecode::LdU64(0), instr];
        let module = make_module(code);
        let fun_context = get_fun_context(&module);
        let result = type_safety::verify(&module, &fun_context, &mut DummyMeter);
        assert!(result.is_ok());
    }
}

#[test]
fn test_cast_wrong_type() {
    for instr in vec![
        Bytecode::CastU8,
        Bytecode::CastU16,
        Bytecode::CastU32,
        Bytecode::CastU64,
        Bytecode::CastU128,
        Bytecode::CastU256,
    ] {
        let code = vec![Bytecode::LdTrue, instr];
        let module = make_module(code);
        let fun_context = get_fun_context(&module);
        let result = type_safety::verify(&module, &fun_context, &mut DummyMeter);
        assert_eq!(
            result.unwrap_err().major_status(),
            StatusCode::INTEGER_OP_TYPE_MISMATCH_ERROR
        );
    }
}

#[test]
#[should_panic]
fn test_cast_no_arg() {
    for instr in vec![
        Bytecode::CastU8,
        Bytecode::CastU16,
        Bytecode::CastU32,
        Bytecode::CastU64,
        Bytecode::CastU128,
        Bytecode::CastU256,
    ] {
        let code = vec![instr];
        let module = make_module(code);
        let fun_context = get_fun_context(&module);
        let _result = type_safety::verify(&module, &fun_context, &mut DummyMeter);
    }
}



#[test]
fn test_arithmetic_correct_types() {
    for instr in vec![
        Bytecode::Add,
        Bytecode::Sub,
        Bytecode::Mul,
        Bytecode::Mod,
        Bytecode::Div,
        Bytecode::BitOr,
        Bytecode::BitAnd,
        Bytecode::Xor,
    ] {
        for push_ty_instr in vec![
            Bytecode::LdU8(42),
            Bytecode::LdU16(257),
            Bytecode::LdU32(89),
            Bytecode::LdU64(94),
            Bytecode::LdU128(Box::new(9999)),
            Bytecode::LdU256(Box::new(U256::from(745_u32))),
        ] {
            let code = vec![push_ty_instr.clone(), push_ty_instr.clone(), instr.clone()];
            let module = make_module(code);
            let fun_context = get_fun_context(&module);
            let result = type_safety::verify(&module, &fun_context, &mut DummyMeter);
            assert!(result.is_ok());
        }
    }
}

#[test]
fn test_arithmetic_mismatched_types() {
    for instr in vec![
        Bytecode::Add,
        Bytecode::Sub,
        Bytecode::Mul,
        Bytecode::Mod,
        Bytecode::Div,
        Bytecode::BitOr,
        Bytecode::BitAnd,
        Bytecode::Xor,
    ] {
        let code = vec![Bytecode::LdU8(42), Bytecode::LdU64(94), instr];
        let module = make_module(code);
        let fun_context = get_fun_context(&module);
        let result = type_safety::verify(&module, &fun_context, &mut DummyMeter);
        assert_eq!(
            result.unwrap_err().major_status(),
            StatusCode::INTEGER_OP_TYPE_MISMATCH_ERROR
        );
    }
}

#[test]
fn test_arithmetic_wrong_type() {
    for instr in vec![
        Bytecode::Add,
        Bytecode::Sub,
        Bytecode::Mul,
        Bytecode::Mod,
        Bytecode::Div,
        Bytecode::BitOr,
        Bytecode::BitAnd,
        Bytecode::Xor,
    ] {
        let code = vec![Bytecode::LdTrue, Bytecode::LdU64(94), instr.clone()];
        let module = make_module(code);
        let fun_context = get_fun_context(&module);
        let result = type_safety::verify(&module, &fun_context, &mut DummyMeter);
        assert_eq!(
            result.unwrap_err().major_status(),
            StatusCode::INTEGER_OP_TYPE_MISMATCH_ERROR
        );

        let code = vec![Bytecode::LdU32(94), Bytecode::LdFalse, instr.clone()];
        let module = make_module(code);
        let fun_context = get_fun_context(&module);
        let result = type_safety::verify(&module, &fun_context, &mut DummyMeter);
        assert_eq!(
            result.unwrap_err().major_status(),
            StatusCode::INTEGER_OP_TYPE_MISMATCH_ERROR
        );
    }
}


#[test]
#[should_panic]
fn test_arithmetic_too_few_args() {
    for instr in vec![
        Bytecode::Add,
        Bytecode::Sub,
        Bytecode::Mul,
        Bytecode::Mod,
        Bytecode::Div,
        Bytecode::BitOr,
        Bytecode::BitAnd,
        Bytecode::Xor,
    ] {
        let code = vec![Bytecode::LdU16(42), instr.clone()];
        let module = make_module(code);
        let fun_context = get_fun_context(&module);
        let _result = type_safety::verify(&module, &fun_context, &mut DummyMeter);

        let code = vec![instr.clone()];
        let module = make_module(code);
        let fun_context = get_fun_context(&module);
        let _result = type_safety::verify(&module, &fun_context, &mut DummyMeter);
    }
}


#[test]
fn test_shl_shr_correct_types() {
    for instr in vec![
        Bytecode::Shl,
        Bytecode::Shr,
    ] {
        for push_ty_instr in vec![
            Bytecode::LdU8(42),
            Bytecode::LdU16(257),
            Bytecode::LdU32(89),
            Bytecode::LdU64(94),
            Bytecode::LdU128(Box::new(9999)),
            Bytecode::LdU256(Box::new(U256::from(745_u32))),
        ] {
            let code = vec![push_ty_instr.clone(), Bytecode::LdU8(2), instr.clone()];
            let module = make_module(code);
            let fun_context = get_fun_context(&module);
            let result = type_safety::verify(&module, &fun_context, &mut DummyMeter);
            assert!(result.is_ok());
        }
    }
}

#[test]
fn test_shl_shr_first_operand_wrong_type() {
    for instr in vec![
        Bytecode::Shl,
        Bytecode::Shr,
    ] {
        let code = vec![Bytecode::LdTrue, Bytecode::LdU8(2), instr.clone()];
        let module = make_module(code);
        let fun_context = get_fun_context(&module);
        let result = type_safety::verify(&module, &fun_context, &mut DummyMeter);
        assert_eq!(
            result.unwrap_err().major_status(),
            StatusCode::INTEGER_OP_TYPE_MISMATCH_ERROR
        );
    }
}

#[test]
fn test_shl_shr_second_operand_wrong_type() {
    for instr in vec![
        Bytecode::Shl,
        Bytecode::Shr,
    ] {
        let code = vec![Bytecode::LdU32(42), Bytecode::LdU16(2), instr.clone()];
        let module = make_module(code);
        let fun_context = get_fun_context(&module);
        let result = type_safety::verify(&module, &fun_context, &mut DummyMeter);
        assert_eq!(
            result.unwrap_err().major_status(),
            StatusCode::INTEGER_OP_TYPE_MISMATCH_ERROR
        );
    }
}

#[test]
#[should_panic]
fn test_shl_shr_too_few_args() {
    for instr in vec![
        Bytecode::Shl,
        Bytecode::Shr,
    ] {
        let code = vec![Bytecode::LdU16(42), instr.clone()];
        let module = make_module(code);
        let fun_context = get_fun_context(&module);
        let _result = type_safety::verify(&module, &fun_context, &mut DummyMeter);

        let code = vec![instr.clone()];
        let module = make_module(code);
        let fun_context = get_fun_context(&module);
        let _result = type_safety::verify(&module, &fun_context, &mut DummyMeter);
    }
}


#[test]
fn test_or_and_correct_types() {
    for instr in vec![
        Bytecode::Or,
        Bytecode::And,
    ] {
        let code = vec![Bytecode::LdFalse, Bytecode::LdTrue, instr.clone()];
        let module = make_module(code);
        let fun_context = get_fun_context(&module);
        let result = type_safety::verify(&module, &fun_context, &mut DummyMeter);
        assert!(result.is_ok());
    }
}

#[test]
fn test_or_and_wrong_types() {
    for instr in vec![
        Bytecode::Or,
        Bytecode::And,
    ] {
        let code = vec![Bytecode::LdU32(42), Bytecode::LdTrue, instr.clone()];
        let module = make_module(code);
        let fun_context = get_fun_context(&module);
        let result = type_safety::verify(&module, &fun_context, &mut DummyMeter);
        assert_eq!(
            result.unwrap_err().major_status(),
            StatusCode::BOOLEAN_OP_TYPE_MISMATCH_ERROR
        );

        let code = vec![Bytecode::LdTrue, Bytecode::LdU64(42), instr.clone()];
        let module = make_module(code);
        let fun_context = get_fun_context(&module);
        let result = type_safety::verify(&module, &fun_context, &mut DummyMeter);
        assert_eq!(
            result.unwrap_err().major_status(),
            StatusCode::BOOLEAN_OP_TYPE_MISMATCH_ERROR
        );
    }
}

#[test]
#[should_panic]
fn test_or_and_too_few_args() {
    for instr in vec![
        Bytecode::Or,
        Bytecode::And,
    ] {
        let code = vec![Bytecode::LdTrue, instr.clone()];
        let module = make_module(code);
        let fun_context = get_fun_context(&module);
        let _result = type_safety::verify(&module, &fun_context, &mut DummyMeter);

        let code = vec![instr.clone()];
        let module = make_module(code);
        let fun_context = get_fun_context(&module);
        let _result = type_safety::verify(&module, &fun_context, &mut DummyMeter);
    }
}


#[test]
fn test_not_correct_type() {
    let code = vec![Bytecode::LdFalse, Bytecode::Not];
    let module = make_module(code);
    let fun_context = get_fun_context(&module);
    let result = type_safety::verify(&module, &fun_context, &mut DummyMeter);
    assert!(result.is_ok());
}

#[test]
fn test_not_wrong_type() {
    let code = vec![Bytecode::LdU32(42), Bytecode::Not];
    let module = make_module(code);
    let fun_context = get_fun_context(&module);
    let result = type_safety::verify(&module, &fun_context, &mut DummyMeter);
    assert_eq!(
        result.unwrap_err().major_status(),
        StatusCode::BOOLEAN_OP_TYPE_MISMATCH_ERROR
    );
}

#[test]
#[should_panic]
fn test_not_no_arg() {
    let code = vec![Bytecode::Not];
    let module = make_module(code);
    let fun_context = get_fun_context(&module);
    let _result = type_safety::verify(&module, &fun_context, &mut DummyMeter);
}


#[test]
fn test_comparison_correct_types() {
    for instr in vec![
        Bytecode::Lt,
        Bytecode::Gt,
        Bytecode::Le,
        Bytecode::Ge,
        Bytecode::Eq,
        Bytecode::Neq,
    ] {
        for push_ty_instr in vec![
            Bytecode::LdU8(42),
            Bytecode::LdU16(257),
            Bytecode::LdU32(89),
            Bytecode::LdU64(94),
            Bytecode::LdU128(Box::new(9999)),
            Bytecode::LdU256(Box::new(U256::from(745_u32))),
        ] {
            let code = vec![push_ty_instr.clone(), push_ty_instr.clone(), instr.clone()];
            let module = make_module(code);
            let fun_context = get_fun_context(&module);
            let result = type_safety::verify(&module, &fun_context, &mut DummyMeter);
            assert!(result.is_ok());
        }
    }
}

#[test]
fn test_comparison_mismatched_types() {
    for instr in vec![
        Bytecode::Lt,
        Bytecode::Gt,
        Bytecode::Le,
        Bytecode::Ge,
    ] {
        let code = vec![Bytecode::LdU8(42), Bytecode::LdU64(94), instr.clone()];
        let module = make_module(code);
        let fun_context = get_fun_context(&module);
        let result = type_safety::verify(&module, &fun_context, &mut DummyMeter);
        assert_eq!(
            result.unwrap_err().major_status(),
            StatusCode::INTEGER_OP_TYPE_MISMATCH_ERROR
        );
    }
}

#[test]
fn test_comparison_wrong_type() {
    for instr in vec![
        Bytecode::Lt,
        Bytecode::Gt,
        Bytecode::Le,
        Bytecode::Ge,
    ] {
        let code = vec![Bytecode::LdTrue, Bytecode::LdU64(94), instr.clone()];
        let module = make_module(code);
        let fun_context = get_fun_context(&module);
        let result = type_safety::verify(&module, &fun_context, &mut DummyMeter);
        assert_eq!(
            result.unwrap_err().major_status(),
            StatusCode::INTEGER_OP_TYPE_MISMATCH_ERROR
        );

        let code = vec![Bytecode::LdU32(94), Bytecode::LdFalse, instr.clone()];
        let module = make_module(code);
        let fun_context = get_fun_context(&module);
        let result = type_safety::verify(&module, &fun_context, &mut DummyMeter);
        assert_eq!(
            result.unwrap_err().major_status(),
            StatusCode::INTEGER_OP_TYPE_MISMATCH_ERROR
        );
    }
}

#[test]
#[should_panic]
fn test_comparison_too_few_args() {
    for instr in vec![
        Bytecode::Lt,
        Bytecode::Gt,
        Bytecode::Le,
        Bytecode::Ge,
    ] {
        let code = vec![Bytecode::LdU16(42), instr.clone()];
        let module = make_module(code);
        let fun_context = get_fun_context(&module);
        let _result = type_safety::verify(&module, &fun_context, &mut DummyMeter);

        let code = vec![instr.clone()];
        let module = make_module(code);
        let fun_context = get_fun_context(&module);
        let _result = type_safety::verify(&module, &fun_context, &mut DummyMeter);
    }
}


// these operation does not produce errors in verify_instr()
#[test]
fn test_branch_nop_ok() {
    for instr in vec![
        Bytecode::Branch(0),
        Bytecode::Nop,
    ] {
        let code = vec![instr];
        let module = make_module(code);
        let fun_context = get_fun_context(&module);
        let result = type_safety::verify(&module, &fun_context, &mut DummyMeter);
        assert!(result.is_ok());
    }
}


#[test]
fn test_ld_integers_ok() {
    for instr in vec![
        Bytecode::LdU8(42),
        Bytecode::LdU16(257),
        Bytecode::LdU32(89),
        Bytecode::LdU64(94),
        Bytecode::LdU128(Box::new(9999)),
        Bytecode::LdU256(Box::new(U256::from(745_u32))),
    ] {
        let code = vec![instr];
        let module = make_module(code);
        let fun_context = get_fun_context(&module);
        let result = type_safety::verify(&module, &fun_context, &mut DummyMeter);
        assert!(result.is_ok());
    }
}

