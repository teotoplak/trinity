import scipy.stats as st
import numpy


def _distance_expectation_matrix_markov(transition_matrix):
    transition_matrix = transition_matrix[:-1, :-1]
    return numpy.linalg.inv(numpy.identity(len(transition_matrix)) - transition_matrix)


def _distance_transition_matrix_markov(network_size, malicious_nodes_number, neighbours_response_size):
    s = (malicious_nodes_number + 1, malicious_nodes_number + 1)
    result_matrix = numpy.zeros(s)
    for row in range(malicious_nodes_number + 1):
        for column in range(malicious_nodes_number + 1):
            if row > column:
                continue
            else:
                result_matrix[row][column] = st.hypergeom(network_size,
                                                          malicious_nodes_number - row,
                                                          neighbours_response_size).pmf(column - row)
    return result_matrix


def calculate_distance(network_size, malicious_nodes_number, neighbours_response_size):
    """Calculates minimum suggested walk length over the network for aurora algorithm"""
    transition_matrix = _distance_transition_matrix_markov(network_size, malicious_nodes_number, neighbours_response_size)
    network_size = _distance_expectation_matrix_markov(transition_matrix)
    return sum(network_size[0, :])

