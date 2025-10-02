use criterion::{black_box, criterion_group, criterion_main, Criterion};
use zkp::ZKP;

fn benchmark_zkp_operations(c: &mut Criterion) {
    let zkp = ZKP::new(None).unwrap();
    let x = ZKP::generate_random_number_below(&zkp.q).unwrap();
    let k = ZKP::generate_random_number_below(&zkp.q).unwrap();
    let c_value = ZKP::generate_random_number_below(&zkp.q).unwrap();

    c.bench_function("compute_pair", |b| {
        b.iter(|| zkp.compute_pair(black_box(&x)).unwrap())
    });

    let (y1, y2) = zkp.compute_pair(&x).unwrap();
    let (r1, r2) = zkp.compute_pair(&k).unwrap();

    c.bench_function("solve", |b| {
        b.iter(|| {
            zkp.solve(black_box(&k), black_box(&c_value), black_box(&x))
                .unwrap()
        })
    });

    let s = zkp.solve(&k, &c_value, &x).unwrap();

    c.bench_function("verify", |b| {
        b.iter(|| {
            zkp.verify(
                black_box(&r1),
                black_box(&r2),
                black_box(&y1),
                black_box(&y2),
                black_box(&c_value),
                black_box(&s),
            )
            .unwrap()
        })
    });

    c.bench_function("full_zkp_flow", |b| {
        b.iter(|| {
            let x = ZKP::generate_random_number_below(&zkp.q).unwrap();
            let k = ZKP::generate_random_number_below(&zkp.q).unwrap();
            let c = ZKP::generate_random_number_below(&zkp.q).unwrap();

            let (y1, y2) = zkp.compute_pair(&x).unwrap();
            let (r1, r2) = zkp.compute_pair(&k).unwrap();
            let s = zkp.solve(&k, &c, &x).unwrap();
            let result = zkp.verify(&r1, &r2, &y1, &y2, &c, &s).unwrap();
            
            black_box(result)
        })
    });
}

criterion_group!(benches, benchmark_zkp_operations);
criterion_main!(benches);