import pytest
from pytest import approx
from p2p.aurora.distance import calculate_distance, _distance_expectation_matrix_markov, \
    _distance_transition_matrix_markov


absolute_tolerance = 10e-2


def assert_matrices_equal(expected, result):
    # matrices have to be same size
    assert len(expected) == len(result) and len(expected[0]) == len(result[0])
    for row_index in range(len(result)):
        assert result[row_index] == approx(expected[row_index], abs=absolute_tolerance)


def test_aurora_distance_5():
    assert calculate_distance(5, 3, 2) == approx(4.325, abs=absolute_tolerance)


def test_aurora_distance_52():
    assert calculate_distance(52, 26, 5) == approx(38.947, abs=absolute_tolerance)


def test_aurora_distance_100():
    assert calculate_distance(100, 30, 10) == approx(38.535, abs=absolute_tolerance)


# test disabled since it is computationally demanding and takes longer time
#
# def test_aurora_distance_1000():
#    assert expected_draws(1000, 499, 40) == approx(166.9329, abs=absolute_tolerance)


def test_draw_amount_expectation_matrix_markov():
    expected = [[1.111, 0.95238, 2.26190],
                [0, 1.42857, 2.14286],
                [0, 0, 2.5]]
    transition_matrix = _distance_transition_matrix_markov(5, 3, 2)
    result_matrix = _distance_expectation_matrix_markov(transition_matrix)
    assert_matrices_equal(expected, result_matrix)


def test_draw_amount_transition_matrix_markov():
    expected = [[0.10000,   0.60000,   0.30000,   0.00000],
                [0.00000,   0.30000,   0.60000,   0.10000],
                [0.00000,   0.00000,   0.60000,   0.40000],
                [0.00000,   0.00000,   0.00000,   1.00000]]
    result = _distance_transition_matrix_markov(5, 3, 2)
    assert_matrices_equal(expected, result)


